import sys
import json
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PySide6.QtWebEngineWidgets import QWebEngineView

class CFGVisualizerWindow(QMainWindow):
    """
    负责承载网页的 PyQt 窗口类
    """
    def __init__(self, nodes_data, edges_data, sparsity=1.0):
        super().__init__()
        self.setWindowTitle("Angr De-obfuscated CFG Visualizer - Dark Mode")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("QMainWindow { background-color: #1E1E1E; }")

        self.browser = QWebEngineView()
        # 将稀疏因子传入 HTML 生成器
        html_content = self.generate_html(nodes_data, edges_data, sparsity)
        self.browser.setHtml(html_content)

        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.browser)
        central_widget.setLayout(layout)
        
        self.setCentralWidget(central_widget)

    def generate_html(self, nodes, edges, sparsity):
        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)

        # 根据传入的 sparsity 因子动态计算物理参数
        # 默认斥力为 -150，弹簧长度为 150
        calc_gravity = int(-150 * sparsity)
        calc_spring = int(150 * sparsity)

        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Advanced CFG Visualizer</title>
            <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <style type="text/css">
                body, html {{ margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; background-color: #1E1E1E; }}
                #mynetwork {{ width: 100%; height: 100%; outline: none; }}
            </style>
        </head>
        <body>
            <div id="mynetwork"></div>
            <script type="text/javascript">
                var nodes = new vis.DataSet({nodes_json});
                var edges = new vis.DataSet({edges_json});
                var container = document.getElementById('mynetwork');
                var data = {{ nodes: nodes, edges: edges }};
                
                var options = {{
                    edges: {{
                        arrows: {{ to: {{ enabled: true, scaleFactor: 1.2, type: 'arrow' }} }},
                        smooth: {{ enabled: true, type: 'cubicBezier', roundness: 0.5 }},
                        width: 1.5, hoverWidth: 2, selectionWidth: 3,
                        font: {{ size: 12, align: 'middle', strokeWidth: 0, color: '#A5D6A7' }}
                    }},
                    nodes: {{
                        shape: 'box',
                        margin: {{ top: 15, right: 20, bottom: 15, left: 20 }},
                        borderWidth: 2, borderWidthSelected: 4,
                        color: {{
                            highlight: {{ background: '#333344', border: '#FFFFFF' }},
                            hover: {{ background: '#3E3E42', border: '#FFFFFF' }}
                        }},
                        shadow: {{ enabled: true, color: 'rgba(0,0,0,0.5)', size: 10, x: 5, y: 5 }}
                    }},
                    physics: {{
                        enabled: true,
                        solver: 'forceAtlas2Based',
                        forceAtlas2Based: {{
                            gravitationalConstant: {calc_gravity},  /* 动态生成的节点斥力 */
                            centralGravity: 0.01,
                            springConstant: 0.08,
                            springLength: {calc_spring}             /* 动态生成的弹簧长度 */
                        }},
                        stabilization: {{ iterations: 200 }}
                    }},
                    interaction: {{ dragNodes: true, hover: true, navigationButtons: true, keyboard: true }}
                }};

                var network = new vis.Network(container, data, options);
            </script>
        </body>
        </html>
        """
        return html_template


class CFGVisualizer:
    """
    对外暴露的可视化控制器类
    """
    def __init__(self):
        self.app = QApplication.instance()
        if not self.app:
            self.app = QApplication(sys.argv)

    def show_graph(self, processed_blocks, transitions, block_codes=None, sparsity=1.0):
        """
        接收 angr 跑出的数据并进行渲染
        :param processed_blocks: list/set, 所有发现的真实块地址 (int)
        :param transitions: list of tuples, 格式为 [(src_addr, dst_addr, r10_val), ...]
        :param block_codes: dict, 格式为 {addr: "汇编代码文本"}，可选
        :param sparsity: float, 节点稀疏程度因子。1.0 为默认，>1.0 更稀疏，<1.0 更紧凑。
        """
        nodes_data = []
        edges_data = []

        for addr in processed_blocks:
            label_text = f"Block: 0x{addr:x}"
            if block_codes and addr in block_codes:
                label_text += f"\n{block_codes[addr]}"

            nodes_data.append({
                "id": hex(addr),
                "label": label_text,
                "color": {"background": "#2D2D30", "border": "#007ACC"},
                "font": {"color": "#D4D4D4", "face": "Consolas, monospace", "align": "left", "size": 14}
            })

        for src, dst, r10_val in transitions:
            edges_data.append({
                "from": hex(src),
                "to": hex(dst),
                "label": f"r10 = {hex(r10_val)}" if isinstance(r10_val, int) else f"r10 = {r10_val}",
                "color": {"color": "#666666"}
            })

        print(f"[*] 准备渲染图：共 {len(nodes_data)} 个节点, {len(edges_data)} 条边 (稀疏度: {sparsity}x)...")
        
        # 将 sparsity 传递给窗口类
        self.window = CFGVisualizerWindow(nodes_data, edges_data, sparsity)
        self.window.show()
        
        self.app.exec()


# ==========================================
# 测试与调用示例
# ==========================================
if __name__ == "__main__":
    mock_processed = {0x401000, 0x401020, 0x401050, 0x401080}
    mock_transitions = [
        (0x401000, 0x401020, 0x1111), 
        (0x401000, 0x401050, 0x2222),
        (0x401050, 0x401080, 0x3333),
        (0x401080, 0x401020, 0x4444)   
    ]
    mock_asm = {
        0x401000: "mov r10, 0x1111\ncmp eax, 1\nje 0x401050",
        0x401080: "add rbx, 1\njmp dispatcher"
    }

    visualizer = CFGVisualizer()
    
    # 你可以修改 sparsity 的值来观察变化。
    # 比如设置为 2.5，节点之间就会被远远地推开，非常适合超大代码块或长文本的展示。
    visualizer.show_graph(mock_processed, mock_transitions, block_codes=mock_asm, sparsity=2.5)