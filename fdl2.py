import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import networkx as nx
from scipy.spatial import cKDTree
import matplotlib.patches as patches
import time

class QuadTreeNode:
    """四叉树节点，用于Barnes-Hut算法"""
    def __init__(self, x_min, y_min, x_max, y_max):
        self.x_min = x_min
        self.y_min = y_min
        self.x_max = x_max
        self.y_max = y_max
        self.center_of_mass = np.zeros(2)
        self.total_mass = 0.0
        self.children = [None, None, None, None]  # 四个象限
        self.node_index = None  # 如果该节点包含单个节点，存储其索引
        self.width = x_max - x_min
        self.height = y_max - y_min
        
    def contains(self, pos):
        """检查点是否在节点区域内"""
        return (self.x_min <= pos[0] <= self.x_max and 
                self.y_min <= pos[1] <= self.y_max)
    
    def is_leaf(self):
        """检查是否为叶子节点"""
        return all(child is None for child in self.children)
    
    def get_quadrant(self, pos):
        """确定点所在的象限"""
        x_mid = (self.x_min + self.x_max) / 2
        y_mid = (self.y_min + self.y_max) / 2
        
        if pos[0] < x_mid:
            if pos[1] < y_mid:
                return 0  # 左下
            else:
                return 1  # 左上
        else:
            if pos[1] < y_mid:
                return 2  # 右下
            else:
                return 3  # 右上

class BarnesHutForceDirectedLayout:
    def __init__(self, edges, num_nodes, areas=None,
                 repulsion_constant=100.0, 
                 spring_constant=0.1, 
                 spring_length=1.0,
                 damping=0.1,
                 theta=0.5,  # Barnes-Hut近似参数
                 initial_temperature=10.0,
                 cooling_factor=0.95,
                 max_move_distance=0.5,
                 max_iter=100):
        """
        初始化Barnes-Hut优化的力导向布局算法
        
        参数:
        edges -- 边列表，每个元素为(node1, node2)
        num_nodes -- 节点总数
        areas -- 节点面积列表，用于表示质量
        repulsion_constant -- 斥力常数
        spring_constant -- 弹簧常数
        spring_length -- 弹簧自然长度
        damping -- 阻尼系数
        theta -- Barnes-Hut近似阈值
        initial_temperature -- 模拟退火初始温度
        cooling_factor -- 温度衰减系数
        max_move_distance -- 最大移动距离限制
        max_iter -- 最大迭代次数
        """
        self.edges = edges
        self.num_nodes = num_nodes
        self.repulsion_constant = repulsion_constant
        self.spring_constant = spring_constant
        self.spring_length = spring_length
        self.damping = damping
        self.theta = theta
        self.initial_temperature = initial_temperature
        self.temperature = initial_temperature
        self.cooling_factor = cooling_factor
        self.max_move_distance = max_move_distance
        self.max_iter = max_iter
        
        # 节点面积（质量）
        if areas is None:
            self.areas = np.ones(num_nodes)  # 默认所有节点面积为1
        else:
            self.areas = np.array(areas)
        
        # 初始化位置：在单位正方形内随机分布
        self.positions = np.random.rand(num_nodes, 2) * 20 - 10
        
        # 初始化速度
        self.velocities = np.zeros((num_nodes, 2))
        
        # 存储每次迭代的位置用于动画
        self.position_history = [self.positions.copy()]
        
        # 存储能量历史
        self.energy_history = []
        
        # 存储四叉树用于可视化
        self.quadtrees = []

    def calculate_energy(self):
        """计算系统的总能量"""
        total_energy = 0.0
        
        # 1. 计算斥力能量（使用Barnes-Hut近似）
        root = self.build_quadtree()
        for i in range(self.num_nodes):
            total_energy += self._calculate_repulsion_energy(i, root)
        
        # 2. 计算引力能量
        for edge in self.edges:
            i, j = edge
            distance = np.linalg.norm(self.positions[i] - self.positions[j])
            displacement = distance - self.spring_length
            total_energy += 0.5 * self.spring_constant * displacement**2
        
        return total_energy

    def build_quadtree(self):
        """构建四叉树数据结构"""
        # 确定边界
        min_x, min_y = np.min(self.positions, axis=0)
        max_x, max_y = np.max(self.positions, axis=0)
        
        # 添加边界填充
        padding = (max_x - min_x) * 0.1
        min_x -= padding
        max_x += padding
        min_y -= padding
        max_y += padding
        
        # 创建根节点
        root = QuadTreeNode(min_x, min_y, max_x, max_y)
        
        # 插入所有节点
        for i in range(self.num_nodes):
            self._insert_node(root, i, self.positions[i])
        
        # 计算每个节点的质心和总质量
        self._compute_mass_properties(root)
        
        # 存储四叉树用于可视化
        self.quadtrees.append(root)
        return root

    def _insert_node(self, node, index, pos):
        """递归插入节点到四叉树"""
        # 如果节点不包含任何节点，直接添加
        if node.node_index is None and node.is_leaf():
            node.node_index = index
            node.center_of_mass = pos
            node.total_mass = self.areas[index]
            return
        
        # 如果当前节点已经有一个节点，需要分裂
        if node.is_leaf():
            # 保存现有节点
            existing_index = node.node_index
            existing_pos = node.center_of_mass.copy()
            node.node_index = None
            
            # 分裂节点
            quadrant = node.get_quadrant(existing_pos)
            self._create_child(node, quadrant)
            self._insert_node(node.children[quadrant], existing_index, existing_pos)
        
        # 插入新节点
        quadrant = node.get_quadrant(pos)
        if node.children[quadrant] is None:
            self._create_child(node, quadrant)
        
        self._insert_node(node.children[quadrant], index, pos)

    def _create_child(self, parent, quadrant):
        """创建子象限"""
        x_mid = (parent.x_min + parent.x_max) / 2
        y_mid = (parent.y_min + parent.y_max) / 2
        
        if quadrant == 0:  # 左下
            child = QuadTreeNode(parent.x_min, parent.y_min, x_mid, y_mid)
        elif quadrant == 1:  # 左上
            child = QuadTreeNode(parent.x_min, y_mid, x_mid, parent.y_max)
        elif quadrant == 2:  # 右下
            child = QuadTreeNode(x_mid, parent.y_min, parent.x_max, y_mid)
        else:  # 右上 (quadrant == 3)
            child = QuadTreeNode(x_mid, y_mid, parent.x_max, parent.y_max)
        
        parent.children[quadrant] = child

    def _compute_mass_properties(self, node):
        """递归计算每个节点的质心和总质量"""
        if node.is_leaf():
            if node.node_index is not None:
                return node.center_of_mass, node.total_mass
            return np.zeros(2), 0.0
        
        total_mass = 0.0
        com = np.zeros(2)
        
        for child in node.children:
            if child is not None:
                child_com, child_mass = self._compute_mass_properties(child)
                if child_mass > 0:
                    com += child_com * child_mass
                    total_mass += child_mass
        
        if total_mass > 0:
            node.center_of_mass = com / total_mass
            node.total_mass = total_mass
        
        return node.center_of_mass, node.total_mass

    def _calculate_repulsion_energy(self, i, node):
        """计算节点i与四叉树节点的斥力能量"""
        if node.total_mass == 0:
            return 0.0
        
        vector = self.positions[i] - node.center_of_mass
        distance = np.linalg.norm(vector)
        
        # 如果是同一个节点，跳过
        if distance < 1e-5:
            return 0.0
        
        # 如果满足Barnes-Hut条件，使用近似
        if node.width / distance < self.theta or node.is_leaf():
            if node.node_index == i:  # 跳过自身
                return 0.0
            return self.repulsion_constant * self.areas[i] * node.total_mass / distance
        
        # 否则递归处理子节点
        energy = 0.0
        for child in node.children:
            if child is not None:
                energy += self._calculate_repulsion_energy(i, child)
        return energy

    def calculate_repulsion_forces(self, i, node):
        """计算节点i与四叉树节点的斥力"""
        if node.total_mass == 0:
            return np.zeros(2)
        
        vector = self.positions[i] - node.center_of_mass
        distance = np.linalg.norm(vector)
        
        # 如果是同一个节点，跳过
        if distance < 1e-5:
            return np.zeros(2)
        
        # 如果满足Barnes-Hut条件，使用近似
        if node.width / distance < self.theta or node.is_leaf():
            if node.node_index == i:  # 跳过自身
                return np.zeros(2)
            
            # 计算斥力大小（考虑质量）
            force_magnitude = self.repulsion_constant * self.areas[i] * node.total_mass / (distance ** 2)
            return force_magnitude * (vector / distance)
        
        # 否则递归处理子节点
        force = np.zeros(2)
        for child in node.children:
            if child is not None:
                force += self.calculate_repulsion_forces(i, child)
        return force

    def calculate_forces(self):
        """计算所有节点上的合力"""
        forces = np.zeros((self.num_nodes, 2))
        
        # 构建四叉树
        root = self.build_quadtree()
        
        # 1. 计算斥力：使用Barnes-Hut优化
        for i in range(self.num_nodes):
            forces[i] += self.calculate_repulsion_forces(i, root)
        
        # 2. 计算引力：弹簧力（胡克定律）
        for edge in self.edges:
            i, j = edge
            
            # 计算节点间的向量和距离
            vector = self.positions[i] - self.positions[j]
            distance = np.linalg.norm(vector)
            
            # 防止距离为零
            if distance < 0.1:
                distance = 0.1
                vector = np.random.rand(2) * 0.1
            
            # 计算弹簧力（与距离和自然长度的差成正比）
            displacement = distance - self.spring_length
            force_magnitude = self.spring_constant * displacement
            
            # 计算力向量
            force_vector = force_magnitude * (vector / distance)
            
            # 应用牛顿第三定律
            forces[i] -= force_vector
            forces[j] += force_vector
        
        return forces

    def update_positions(self, forces):
        """更新节点位置和速度，考虑质量"""
        # 计算加速度 (F = ma, a = F/m)
        # 使用节点面积作为质量的代理
        accelerations = forces / self.areas[:, np.newaxis]
        
        # 更新速度 (加入阻尼项减少振荡)
        self.velocities = (1 - self.damping) * self.velocities + accelerations
        
        # 应用温度衰减：限制最大速度
        max_velocity = self.temperature
        velocity_norms = np.linalg.norm(self.velocities, axis=1)
        mask = velocity_norms > max_velocity
        if np.any(mask):
            scale_factors = max_velocity / velocity_norms[mask]
            self.velocities[mask] = (self.velocities[mask].T * scale_factors).T
        
        # 更新位置
        new_positions = self.positions + self.velocities
        
        # 应用最大移动距离限制
        move_distances = np.linalg.norm(new_positions - self.positions, axis=1)
        mask = move_distances > self.max_move_distance
        if np.any(mask):
            scale_factors = self.max_move_distance / move_distances[mask]
            displacements = new_positions[mask] - self.positions[mask]
            new_positions[mask] = self.positions[mask] + (displacements.T * scale_factors).T
        
        self.positions = new_positions
        
        # 记录位置历史
        self.position_history.append(self.positions.copy())
        
        # 记录当前能量
        self.energy_history.append(self.calculate_energy())
        
        # 温度衰减（模拟退火）
        self.temperature *= self.cooling_factor

    def run(self):
        """执行力导向布局算法"""
        # 记录初始能量
        self.energy_history.append(self.calculate_energy())
        
        start_time = time.time()
        for i in range(self.max_iter):
            forces = self.calculate_forces()
            self.update_positions(forces)
            
            # 每10次迭代打印进度
            if i % 10 == 0:
                print(f"Iteration {i}/{self.max_iter}, "
                      f"Temperature: {self.temperature:.4f}, "
                      f"Energy: {self.energy_history[-1]:.4f}")
        
        end_time = time.time()
        print(f"Optimization completed in {end_time - start_time:.2f} seconds")

    def plot_graph(self, iteration=None, show_quadtree=False, quad_tree_index=-1):
        """绘制当前布局状态"""
        plt.figure(figsize=(12, 10))
        
        # 绘制四叉树结构（可选）
        if show_quadtree and self.quadtrees:
            self._plot_quadtree(self.quadtrees[quad_tree_index])
        
        # 绘制边
        for edge in self.edges:
            i, j = edge
            plt.plot([self.positions[i, 0], self.positions[j, 0]], 
                     [self.positions[i, 1], self.positions[j, 1]], 
                     'b-', alpha=0.2, linewidth=0.5)
        
        # 绘制节点（大小与面积成正比）
        node_sizes = self.areas * 50  # 缩放因子
        plt.scatter(self.positions[:, 0], self.positions[:, 1], 
                    s=node_sizes, c='red', edgecolors='black', alpha=0.7)
        
        plt.title(f'Barnes-Hut Force-Directed Layout (100 Nodes){"" if iteration is None else f" (Iteration {iteration})"}')
        plt.grid(True, alpha=0.3)
        plt.axis('equal')
        plt.tight_layout()
        plt.show()
    
    def _plot_quadtree(self, node):
        """递归绘制四叉树结构"""
        # 绘制当前节点边界
        rect = patches.Rectangle(
            (node.x_min, node.y_min), node.width, node.height,
            linewidth=0.5, edgecolor='gray', facecolor='none', alpha=0.3
        )
        plt.gca().add_patch(rect)
        
        # 绘制质心
        if node.total_mass > 0:
            plt.plot(node.center_of_mass[0], node.center_of_mass[1], 'g+', markersize=5, alpha=0.5)
        
        # 递归绘制子节点
        for child in node.children:
            if child is not None:
                self._plot_quadtree(child)
    
    def plot_energy_history(self):
        """绘制能量变化曲线"""
        plt.figure(figsize=(10, 6))
        plt.plot(self.energy_history, 'b-', linewidth=2)
        plt.xlabel('Iteration')
        plt.ylabel('System Energy')
        plt.title('Energy Reduction During Layout Optimization')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.show()
    
    def animate_layout(self, save_as=None, show_quadtree=False):
        """创建布局动画"""
        fig, ax = plt.subplots(figsize=(12, 10))
        
        # 设置坐标轴范围
        min_pos = np.min(self.positions)
        max_pos = np.max(self.positions)
        padding = (max_pos - min_pos) * 0.1
        ax.set_xlim(min_pos - padding, max_pos + padding)
        ax.set_ylim(min_pos - padding, max_pos + padding)
        
        ax.grid(True, alpha=0.3)
        ax.set_title('Barnes-Hut Force-Directed Layout Animation (100 Nodes)')
        
        # 初始化边
        lines = []
        for edge in self.edges:
            line, = ax.plot([], [], 'b-', alpha=0.2, linewidth=0.5)
            lines.append(line)
        
        # 初始化节点（大小与面积成正比）
        node_sizes = self.areas * 50  # 缩放因子
        # nodes = ax.scatter([], [], s=node_sizes, c='red', edgecolors='black', alpha=0.7)
        nodes = ax.scatter([], [], s=[], c='red', edgecolors='black', alpha=0.7)
        
        # 初始化四叉树可视化
        quadtree_rects = []
        
        def init():
            """初始化动画"""
            return lines + [nodes]
        
        def update(frame):
            """更新动画帧"""
            pos = self.position_history[frame]
            
            # 更新边
            for idx, edge in enumerate(self.edges):
                i, j = edge
                x_data = [pos[i, 0], pos[j, 0]]
                y_data = [pos[i, 1], pos[j, 1]]
                lines[idx].set_data(x_data, y_data)
            
            # 更新节点
            nodes.set_offsets(pos)
            
            # 更新四叉树可视化（如果启用）
            if show_quadtree and frame < len(self.quadtrees):
                # 清除之前的矩形
                for rect in quadtree_rects:
                    rect.remove()
                quadtree_rects.clear()
                
                # 绘制当前四叉树
                self._add_quadtree_to_plot(self.quadtrees[frame], ax, quadtree_rects)
            
            ax.set_title(f'Barnes-Hut Layout (Iteration {frame}, Energy: {self.energy_history[frame]:.2f})')
            return lines + [nodes] + quadtree_rects
        
        # 创建动画
        ani = animation.FuncAnimation(fig, update, frames=len(self.position_history), 
                                     init_func=init, interval=50, blit=True)
        
        # 保存动画（如果指定了文件名）
        if save_as:
            print(f"Saving animation to {save_as}...")
            ani.save(save_as, writer='pillow', fps=15)
        
        plt.close()
        return ani
    
    def _add_quadtree_to_plot(self, node, ax, rect_list):
        """递归添加四叉树到绘图"""
        # 绘制当前节点边界
        rect = patches.Rectangle(
            (node.x_min, node.y_min), node.width, node.height,
            linewidth=0.5, edgecolor='gray', facecolor='none', alpha=0.3
        )
        ax.add_patch(rect)
        rect_list.append(rect)
        
        # 绘制质心
        if node.total_mass > 0:
            centroid, = ax.plot(node.center_of_mass[0], node.center_of_mass[1], 
                               'g+', markersize=5, alpha=0.5)
            rect_list.append(centroid)
        
        # 递归绘制子节点
        for child in node.children:
            if child is not None:
                self._add_quadtree_to_plot(child, ax, rect_list)

# 生成100个节点的随机图
def generate_random_graph(n_nodes=100, edge_prob=0.03):
    """生成随机图"""
    G = nx.fast_gnp_random_graph(n_nodes, edge_prob)
    while not nx.is_connected(G):
        # 确保图是连通的
        edge_prob += 0.01
        G = nx.fast_gnp_random_graph(n_nodes, edge_prob)
    
    # 转换为边列表
    edges = list(G.edges())
    return edges, n_nodes

# 生成随机节点面积
def generate_random_areas(num_nodes, min_area=0.5, max_area=5.0):
    """生成随机节点面积"""
    return np.random.uniform(min_area, max_area, num_nodes)

# 示例用法
if __name__ == "__main__":
    np.random.seed(42)  # 设置随机种子以保证可重复性
    
    # 生成100个节点的随机图
    print("Generating random graph with 100 nodes...")
    edges, num_nodes = generate_random_graph(100, 0.03)
    print(f"Graph generated with {num_nodes} nodes and {len(edges)} edges.")
    
    # 生成随机节点面积
    areas = generate_random_areas(num_nodes)
    
    # 创建布局实例
    layout = BarnesHutForceDirectedLayout(
        edges, num_nodes, areas=areas,
        repulsion_constant=150.0,
        spring_constant=0.15,
        spring_length=2.0,
        damping=0.15,
        theta=0.7,  # Barnes-Hut阈值
        initial_temperature=20.0,
        cooling_factor=0.93,
        max_move_distance=1.0,
        max_iter=100
    )
    
    # 运行布局算法
    print("Running Barnes-Hut optimized force-directed layout algorithm...")
    layout.run()
    
    # 显示最终布局
    print("Plotting final layout...")
    layout.plot_graph(show_quadtree=True)
    
    # 绘制能量变化曲线
    print("Plotting energy history...")
    layout.plot_energy_history()
    
    # 创建并显示动画（并保存为gif）
    print("Creating animation...")
    ani = layout.animate_layout(save_as="barnes_hut_force_directed.gif", show_quadtree=True)
    
    print("Done!")
