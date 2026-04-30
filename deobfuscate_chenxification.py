import angr, claripy
import networkx as nx
import matplotlib.pyplot as plt

BINARY_PATH = "./examples/rsa_example.exe"
FUNC_ADDR = 0x140001250
DISPATCHER_START = 0x14000128b # 分发器第一条指令 (movsxd rax, r10d)
DISPATCHER_JMP = 0x140001299   # 分发器跳转指令 (jmp rcx)

# 14000128b  movsxd  rax, r10d
# 14000128e  mov     ecx, dword [r15+rax*4+0x1314]
# 140001296  add     rcx, r15
# 140001299  jmp     rcx

def deobfuscate_dispatcher():
    """
    偏移型跳转表
    基于符号执行的广度优先搜索 (BFS)
    """
    
    print("[*] 正在加载二进制文件...")
    # 开启 auto_load_libs=False 加快分析速度
    p = angr.Project(BINARY_PATH, auto_load_libs=False)

    # 获取 r15 的值，基地址；
    # 因为跳转依赖于 r15，我们必须先知道 r15 是多少
    print("[*] 正在执行函数序言，提取基址寄存器 r15...")
    init_state = p.factory.blank_state(addr=FUNC_ADDR)
    simgr_init = p.factory.simulation_manager(init_state)
    simgr_init.explore(find=DISPATCHER_START)
    
    if not simgr_init.found:
        print("[-] 无法从函数入口执行到分发器！")
        return
    
    prologue_state = simgr_init.found[0]
    r15_value = prologue_state.solver.eval(prologue_state.regs.r15)
    print(f"[+] 成功提取 r15 的值: 0x{r15_value:x}")


    # 继续单步执行，穿过分发器，直到跳出分发器范围
    disp_simgr = p.factory.simulation_manager(prologue_state)
    while disp_simgr.active:
        current_addr = disp_simgr.active[0].addr
        if current_addr < DISPATCHER_START or current_addr > DISPATCHER_JMP:
            break
        disp_simgr.step()

    first_real_block = disp_simgr.active[0].addr
    print(f"[+] 第一个真实块地址: 0x{first_real_block:x}")
    
    print("\n[*] 启动 BFS ，挖掘所有真实块...")
    worklist = [first_real_block]
    processed = set()
    
    transitions = [ ]

    def explore_block(block_addr):
        # state = p.factory.blank_state(addr=block_addr)
        
        # state.regs.r15 = r15_value # 继承基址
        state = prologue_state.copy()
        state.regs.rip = block_addr

        # 2. 核心修复：将参与运算的易失性寄存器和标志位强制“符号化”
        # 这样 cmp r11d, r8d 就会产生不确定的结果，迫使 cmovge 囊括所有可能
        volatile_regs = ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']
        for reg in volatile_regs:
            size = getattr(state.regs, reg).size()
            setattr(state.regs, reg, claripy.BVS(f"sym_{reg}", size))
        
        # 将标志寄存器设为符号化，抹除历史具体的比较结果
        state.regs.eflags = claripy.BVS("sym_eflags", 32)
        
        sm = p.factory.simulation_manager(state)
        # 执行直到抵达分发器
        sm.explore(find=DISPATCHER_START)
        
        results = []
        for found_state in sm.found:
            # 此时 r10 可能是一个包含 0x2 和 0x6 的抽象语法树 (AST)
            # 我们不在这里求值，而是继续往前走
            disp_sm = p.factory.simulation_manager(found_state)
            
            # 3. 核心修复：步进遍历分发器，捕获 angr 的自动分叉 (Fork)
            while disp_sm.active:
                disp_sm.step()
                
                # 检查所有存活的状态
                for s in disp_sm.active[:]:
                    # 如果状态的 PC 飞出了分发器的范围，说明 jmp rcx 发生并完成了分叉
                    if s.addr < DISPATCHER_START or s.addr > DISPATCHER_JMP:
                        disp_sm.active.remove(s)
                        # 将跳出的状态存入自定义的 stash 中
                        disp_sm.stashes.setdefault('exited', []).append(s)
            
            # 4. 在分叉后的分支中提取 r10
            if 'exited' in disp_sm.stashes:
                for target_state in disp_sm.stashes['exited']:
                    target_addr = target_state.addr
                    # 因为 angr 根据目标地址分叉了路径，此时的 r10 被加上了路径约束
                    # eval 此时只会返回在这条唯一路径下 r10 的确定值 (0x2 或 0x6)
                    r10_val = target_state.solver.eval(target_state.regs.r10)
                    results.append((r10_val, target_addr))
                    
        return results

        # simgr = p.factory.simulation_manager(state)
        # # 让真实块执行，直到它再次回到分发器
        # simgr.explore(find=DISPATCHER_START)

        # results = []

        # for found_state in simgr.found:
        #     r10_val = found_state.solver.eval(found_state.regs.r10)
        #     print(f"    -> 状态变量 r10 被设置为: {r10_val}")
        #     disp_simgr = p.factory.simulation_manager(found_state)
            
        #     while disp_simgr.active:
        #         current_addr = disp_simgr.active[0].addr
        #         if current_addr < DISPATCHER_START or current_addr > DISPATCHER_JMP:
        #             # 如果跳转到了其他地方（真实块），跳出循环
        #             break
        #         disp_simgr.step()
                
        #     if disp_simgr.active:
        #         target_addr = disp_simgr.active[0].addr
        #         results.append((r10_val, target_addr))
                
        # return results
    
    while worklist:
        current_block = worklist.pop(0)

        if current_block in processed:
            continue

        processed.add(current_block)

        print(f"    -> 正在符号执行真实块: 0x{current_block:x}")
        next_targets = explore_block(current_block)
        
        if not next_targets:
            print(f"       [!] 块 0x{current_block:x} 没有跳回分发器 (可能是 Return 块)")
            continue
            
        for r10_val, dst_block in next_targets:
            print(f"       [+] r10={r10_val} => 目标块: 0x{dst_block:x}")
            transitions.append((current_block, dst_block, r10_val))
            
            if dst_block not in processed and dst_block not in worklist:
                worklist.append(dst_block)
    
    print(f"\n[*] 分析完成！共发现 {len(processed)} 个真实块。")
    
    
    print("[*] 绘制恢复出的控制流图 (CFG)...")
    # 构建有向图
    G = nx.DiGraph()
    for src, dst, r10 in transitions:
        # 添加边，并将状态变量 r10 的值作为边的标签
        G.add_edge(hex(src), hex(dst), label=f"r10={r10}")

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=42) # 使用弹簧布局
    
    # 绘制节点和边
    nx.draw(G, pos, with_labels=True, node_color='lightgreen', node_size=2000, 
            font_size=10, font_weight='bold', arrows=True, edge_color='gray')
            
    # 绘制边上的状态标签
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='red')

    plt.title("Recovered Flattened CFG")
    plt.show()
    
    
if __name__ == "__main__":
    deobfuscate_dispatcher()