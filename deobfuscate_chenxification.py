import angr, claripy
from visualizer import CFGVisualizer

BINARY_PATH = "./examples/rsa_example.exe"
FUNC_ADDR = 0x140001250
DISPATCHER_START = 0x14000128b # 分发器第一条指令 (movsxd rax, r10d)
DISPATCHER_JMP = 0x140001299   # 分发器跳转指令 (jmp rcx)

VOLATILE_REGS = ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']


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
    # 默认num_find就为 1
    simgr_init.explore(find=DISPATCHER_START, num_find=1)
    
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

        # 继承上下文，保留所有状态变量
        state = prologue_state.copy()
        state.regs.rip = block_addr

        # 将参与运算的易失性寄存器和标志位强制“符号化”
        # 这样 cmp r11d, r8d 就会产生不确定的结果，迫使 cmovge 囊括所有可能
        for reg in VOLATILE_REGS:
            size = getattr(state.regs, reg).size()
            setattr(state.regs, reg, claripy.BVS(f"sym_{reg}", size)) # 设置为 claripy.BVS（符号变量）

        # 将标志寄存器设为符号化，抹除历史具体的比较结果
        state.regs.eflags = claripy.BVS("sym_eflags", 32)

        # 此时这些寄存器都是未知数，迫使程序去探索所有可能的路径
        
        # 当我们符号化之后，继承修改过的状态继续符号执行
        sm = p.factory.simulation_manager(state)
        # 执行直到抵达分发器
        sm.explore(find=DISPATCHER_START)

        if not sm.found:
            print("[-] 未能到达分发器入口，检查条件或路径可行性")
            return
        
        results = []
        for found_state in sm.found:
            """
            由于从真实块结尾到分发器的路径是确定的（没有条件分支），sm.found 通常只有一个状态。
            但是，如果这段路径上存在符号分支，angr 会生成多个满足条件的状态。遍历 sm.found 可以覆盖所有可能性。
            """
            
            # 构建一棵运算树，我们不在这里求值，而是继续往前走
            # 以 found_state 为唯一的初始状态，构建一个新的模拟管理器 disp_sm。
            # 这样接下来的步进、分叉、移除操作都不会影响外面的其他状态，逻辑干净。
            disp_sm = p.factory.simulation_manager(found_state)
            
            # 步进遍历分发器，捕获 angr 的自动分叉 (Fork)
            while disp_sm.active:
                disp_sm.step()
                
                # 由于存在符号分支，angr 会自动产生多个后继状态，每个后继对应一个可能的跳转目标，
                # 并且各自的路径约束中会添加“目标地址等于该具体值”的约束。
                
                # 检查所有存活的状态
                for s in disp_sm.active[:]:
                    # 如果状态的 PC 飞出了分发器的范围，说明 jmp rcx 发生并完成了分叉
                    if s.addr < DISPATCHER_START or s.addr > DISPATCHER_JMP:
                        disp_sm.active.remove(s)
                        # 将跳出的状态存入自定义的 stash 中
                        disp_sm.stashes.setdefault('exited', []).append(s)
            
            # 在分叉后的分支中提取 r10
            if 'exited' in disp_sm.stashes:
                for target_state in disp_sm.stashes['exited']:
                    target_addr = target_state.addr
                    # 因为 angr 根据目标地址分叉了路径，此时的 r10 被加上了路径约束
                    # eval 此时只会返回在这条唯一路径下 r10 的确定值
                    r10_val = target_state.solver.eval(target_state.regs.r10)
                    results.append((r10_val, target_addr))
                    
        return results

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

    
    
    vis = CFGVisualizer()
    vis.show_graph(processed, transitions, sparsity=3.0)
    
if __name__ == "__main__":
    deobfuscate_dispatcher()