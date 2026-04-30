import sys
import json

from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PySide6.QtWebEngineWidgets import QWebEngineView

# ==========================================
# 1. 生成复杂的反汇编 CFG 数据
# ==========================================
def generate_complex_cfg_data():
    """
    模拟从 angr 提取并经过定制化处理的数据。
    在这里展示了如何针对特定节点和边进行独立的高级配置。
    """
    
    # 【节点定制】: 反汇编代码、形状(box)、等宽字体排版(left)、配色
    nodes = [
        {
            "id": "entry",
            "label": "loc_401000 (Entry):\npush    rbp\nmov     rbp, rsp\nsub     rsp, 20h\nmov     DWORD PTR [rbp-4], 0",
            "shape": "box",
            "color": {"background": "#2D2D30", "border": "#007ACC"}, # VSCode 蓝边
            "font": {"color": "#D4D4D4", "face": "Consolas, monospace", "align": "left", "size": 16}
        },
        {
            "id": "loop_header",
            "label": "loc_401010 (Loop Header):\ncmp     DWORD PTR [rbp-4], 10\njge     loc_401040",
            "shape": "box",
            "color": {"background": "#2D2D30", "border": "#FF9800"}, # 橙色边框强调循环头
            "font": {"color": "#D4D4D4", "face": "Consolas, monospace", "align": "left", "size": 16}
        },
        {
            "id": "loop_body",
            "label": "loc_401020 (Loop Body):\nmov     eax, DWORD PTR [rbp-4]\nadd     eax, 1\nmov     DWORD PTR [rbp-4], eax\njmp     loc_401010",
            "shape": "box",
            "color": {"background": "#2D2D30", "border": "#4CAF50"}, # 绿色边框表示正常块
            "font": {"color": "#D4D4D4", "face": "Consolas, monospace", "align": "left", "size": 16}
        },
        {
            "id": "loop_end",
            "label": "loc_401040 (Exit):\nmov     eax, 0\nleave\nret",
            "shape": "box",
            "color": {"background": "#2D2D30", "border": "#E51400"}, # 红色边框表示出口
            "font": {"color": "#D4D4D4", "face": "Consolas, monospace", "align": "left", "size": 16}
        },
        {
            "id": "data_segment",
            "label": ".data:0x405000\nGLOBAL_COUNTER dd 0",
            "shape": "database", # 【形状定制】: 圆柱体，表示数据段
            "color": {"background": "#4D4D4D", "border": "#AAAAAA"},
            "font": {"color": "#569CD6", "face": "Consolas, monospace", "size": 14}
        }
    ]

    # 【连线定制】: 曲率、单双向箭头、颜色、粗细
    edges = [
        # 1. 普通的单向边 (Entry -> Header)
        {
            "from": "entry", "to": "loop_header", 
            "arrows": "to", # 单向
            "color": {"color": "#CCCCCC"},
            "label": "fallthrough", "font": {"color": "#888888", "size": 12, "align": "middle"}
        },
        
        # 2. 条件跳转的 True 分支 (Header -> Body)
        {
            "from": "loop_header", "to": "loop_body",
            "arrows": "to",
            "color": {"color": "#4CAF50"}, # 绿色连线
            "label": "True", "font": {"color": "#4CAF50"}
        },
        
        # 3. 条件跳转的 False 分支 (Header -> Exit)
        {
            "from": "loop_header", "to": "loop_end",
            "arrows": "to",
            "color": {"color": "#E51400"}, # 红色连线
            "label": "False", "font": {"color": "#E51400"}
        },
        
        # 4. 循环回跳边 (Body -> Header) - 【高曲率单向边】
        {
            "from": "loop_body", "to": "loop_header",
            "arrows": "to",
            "color": {"color": "#FF9800", "highlight": "#FFFF00"},
            "smooth": {"type": "curvedCW", "roundness": 0.4}, # 强行设置顺时针弯曲，避免和直连线重叠
            "width": 2, # 加粗
            "label": "back-edge", "font": {"color": "#FF9800"}
        },
        
        # 5. 数据引用关系 (Body <-> Data) - 【双向边示例】
        {
            "from": "loop_body", "to": "data_segment",
            "arrows": "to, from", # 【双向箭头】
            "color": {"color": "#569CD6", "opacity": 0.5}, # 半透明蓝色
            "dashes": True, # 虚线
            "label": "read/write", "font": {"color": "#569CD6"}
        }
    ]

    return nodes, edges

# ==========================================
# 2. 前端 HTML & JS 模板 (注入 vis-network)
# ==========================================
def generate_html(nodes, edges):
    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    # 这里的 options 是全局默认配置，如果在上面的字典中单独配置了，会覆盖这里的全局配置
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Advanced CFG Visualizer</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style type="text/css">
            /* 全局背景色设为深色 */
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
                // 【全局连线配置】
                edges: {{
                    arrows: {{
                        to: {{ enabled: true, scaleFactor: 1.2, type: 'arrow' }}, // 默认箭头大小 1.2 倍
                        from: {{ enabled: false, scaleFactor: 1.2, type: 'arrow' }} 
                    }},
                    smooth: {{
                        enabled: true,
                        type: 'cubicBezier', // 默认曲率类型
                        roundness: 0.5       // 默认弯曲程度
                    }},
                    width: 1.5,
                    hoverWidth: 2, // 鼠标悬停时变粗
                    selectionWidth: 3 // 选中时变粗
                }},
                // 【全局节点配置】
                nodes: {{
                    margin: {{ top: 15, right: 20, bottom: 15, left: 20 }}, // 节点内边距（决定了节点的大小感）
                    borderWidth: 2,
                    borderWidthSelected: 4, // 选中时边框变厚
                    color: {{
                        highlight: {{
                            background: '#333344',
                            border: '#FFFFFF'
                        }},
                        hover: {{
                            background: '#3E3E42',
                            border: '#FFFFFF'
                        }}
                    }},
                    shadow: {{
                        enabled: true,
                        color: 'rgba(0,0,0,0.5)',
                        size: 10,
                        x: 5,
                        y: 5
                    }}
                }},
                // 【物理引擎配置：实现弹簧布局和拖拽微调】
                physics: {{
                    enabled: true,
                    solver: 'forceAtlas2Based', // 这种算法非常适合密集网络和 CFG
                    forceAtlas2Based: {{
                        gravitationalConstant: -200, // 斥力大小
                        centralGravity: 0.01,
                        springConstant: 0.08,    // 弹簧硬度
                        springLength: 200        // 连线的基础长度
                    }},
                    stabilization: {{ iterations: 200 }}
                }},
                // 【交互配置】
                interaction: {{
                    dragNodes: true,   // 允许拖动
                    hover: true,       // 允许悬停特效
                    navigationButtons: true, // 显示缩放控件
                    keyboard: true     // 允许键盘方向键平移
                }}
            }};

            var network = new vis.Network(container, data, options);
            
            // 绑定双击事件：可以在这里向 Python 发回数据
            network.on("doubleClick", function (params) {{
                if (params.nodes.length > 0) {{
                    var nodeId = params.nodes[0];
                    console.log("Double clicked node ID: " + nodeId);
                    // document.title = "CLICKED:" + nodeId; // 简单 hack：通过修改 title 传回 PyQt (非正规但管用)
                }}
            }});
        </script>
    </body>
    </html>
    """
    return html_template

# ==========================================
# 3. PyQt6 桌面应用构建
# ==========================================
class VisualizerWindow(QMainWindow):
    def __init__(self, html_content):
        super().__init__()
        self.setWindowTitle("Angr Advanced CFG Visualizer - Dark Mode")
        self.setGeometry(100, 100, 1400, 900)

        # 设置整个 PyQt 窗口的背景为深色（避免加载 HTML 前的白屏闪烁）
        self.setStyleSheet("QMainWindow { background-color: #1E1E1E; }")

        self.browser = QWebEngineView()
        self.browser.setHtml(html_content)

        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.browser)
        central_widget.setLayout(layout)
        
        self.setCentralWidget(central_widget)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    print("[*] Generating Data...")
    nodes, edges = generate_complex_cfg_data()
    
    print("[*] Rendering View...")
    html = generate_html(nodes, edges)
    
    window = VisualizerWindow(html)
    window.show()
    
    # PyQt6 启动事件循环
    sys.exit(app.exec())