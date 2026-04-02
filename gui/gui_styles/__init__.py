class StyleSheet:
    DARK_THEME = """
    /* ===== 全局样式 ===== */
    * {
        font-family: "Microsoft YaHei", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
        font-size: 13px;
        outline: none;
    }
    
    QMainWindow {
        background-color: #1e1e2e;
        color: #cdd6f4;
    }
    
    QWidget {
        color: #cdd6f4;
        background-color: #1e1e2e;
    }
    
    QToolTip {
        background-color: #313244;
        color: #cdd6f4;
        border: 1px solid #45475a;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 12px;
    }

    /* ===== 侧边栏 ===== */
    QFrame#sidebar {
        background-color: #181825;
        border-right: 1px solid #313244;
        min-width: 240px;
        max-width: 280px;
    }

    QLabel#sidebarTitle {
        color: #cba6f7;
        font-size: 18px;
        font-weight: bold;
    }
    
    QLabel#sidebarVersion {
        color: #6c7086;
        font-size: 11px;
    }
    
    QLabel#categoryLabel {
        color: #89b4fa;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 1px;
        padding-left: 8px;
        margin-top: 12px;
        margin-bottom: 4px;
    }

    QPushButton#navButton {
        text-align: left;
        padding: 8px 12px;
        border: none;
        border-radius: 6px;
        background: transparent;
        color: #a6adc8;
        min-height: 34px;
    }
    
    QPushButton#navButton:hover {
        background-color: #313244;
        color: #cdd6f4;
    }
    
    QPushButton#navButton:checked {
        background-color: #45475a;
        color: #89b4fa;
        border-left: 3px solid #89b4fa;
    }
    
    QPushButton#navButton[running="true"] {
        background-color: rgba(166, 227, 161, 0.15);
        color: #a6e3a1;
        border-left: 3px solid #a6e3a1;
    }

    /* ===== 主内容区 ===== */
    QFrame#mainContent {
        background-color: #1e1e2e;
        border: none;
    }

    /* ===== 标题栏 ===== */
    QFrame#titleBar {
        background-color: #181825;
        border-bottom: 1px solid #313244;
        min-height: 48px;
    }
    
    QLabel#titleLabel {
        color: #cdd6f4;
        font-size: 16px;
        font-weight: 600;
    }
    
    QLabel#projectLabel {
        color: #6c7086;
        font-size: 12px;
    }
    
    QLabel#projectNameLabel {
        color: #89b4fa;
        font-size: 12px;
        font-weight: 500;
    }

    /* ===== 卡片样式 ===== */
    QFrame#card {
        background-color: #181825;
        border: 1px solid #313244;
        border-radius: 12px;
    }
    
    QFrame#card:hover {
        border-color: #45475a;
    }

    /* ===== 按钮样式 ===== */
    QPushButton#primaryButton {
        background-color: #89b4fa;
        color: #1e1e2e;
        border: none;
        border-radius: 4px;
        padding: 6px 16px;
        font-weight: 600;
        font-size: 13px;
    }
    
    QPushButton#primaryButton:hover {
        background-color: #74c7ec;
    }
    
    QPushButton#primaryButton:pressed {
        background-color: #89dceb;
    }
    
    QPushButton#primaryButton:disabled {
        background-color: #45475a;
        color: #6c7086;
    }

    QPushButton#secondaryButton {
        background-color: #313244;
        color: #cdd6f4;
        border: 1px solid #45475a;
        border-radius: 6px;
        padding: 8px 16px;
        text-align: left;
    }
    
    QPushButton#secondaryButton:hover {
        background-color: #45475a;
        border-color: #585b70;
    }
    
    QPushButton#dangerButton {
        background-color: #f38ba8;
        color: #1e1e2e;
        border: none;
        border-radius: 4px;
        padding: 6px 16px;
        font-weight: 600;
    }
    
    QPushButton#dangerButton:hover {
        background-color: #eba0ac;
    }
    
    QPushButton#successButton {
        background-color: #a6e3a1;
        color: #1e1e2e;
        border: none;
        border-radius: 8px;
        padding: 10px 24px;
        font-weight: 600;
    }
    
    QPushButton#successButton:hover {
        background-color: #94e2d5;
    }

    QPushButton#iconButton {
        background-color: transparent;
        border: 1px solid #45475a;
        border-radius: 6px;
        padding: 8px;
        min-width: 36px;
        min-height: 36px;
        color: #a6adc8;
    }
    
    QPushButton#iconButton:hover {
        background-color: #313244;
        color: #cdd6f4;
        border-color: #585b70;
    }

    /* ===== 输入框样式 ===== */
    QLineEdit {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        padding: 10px 14px;
        color: #cdd6f4;
        selection-background-color: #45475a;
        min-height: 20px;
    }
    
    QLineEdit:focus {
        border-color: #89b4fa;
    }
    
    QLineEdit:read-only {
        background-color: #1e1e2e;
        color: #6c7086;
    }
    
    QLineEdit::placeholder {
        color: #6c7086;
    }

    QTextEdit {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        color: #cdd6f4;
        selection-background-color: #45475a;
        padding: 10px;
    }
    
    QTextEdit:focus {
        border-color: #89b4fa;
    }

    QPlainTextEdit {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        color: #cdd6f4;
        selection-background-color: #45475a;
        padding: 10px;
    }
    
    QPlainTextEdit:focus {
        border-color: #89b4fa;
    }

    /* ===== 下拉框样式 ===== */
    QComboBox {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        padding: 10px 14px;
        color: #cdd6f4;
        min-height: 20px;
    }
    
    QComboBox:focus {
        border-color: #89b4fa;
    }
    
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 30px;
        border: none;
        border-top-right-radius: 8px;
        border-bottom-right-radius: 8px;
    }
    
    QComboBox::down-arrow {
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid #6c7086;
        margin-right: 10px;
    }
    
    QComboBox QAbstractItemView {
        background-color: #181825;
        border: 1px solid #45475a;
        border-radius: 8px;
        padding: 4px;
        selection-background-color: #45475a;
        selection-color: #cdd6f4;
        outline: none;
        color: #cdd6f4;
    }
    
    QComboBox QAbstractItemView::item {
        padding: 8px 12px;
        min-height: 28px;
        border-radius: 4px;
        color: #cdd6f4;
    }
    
    QComboBox QAbstractItemView::item:hover {
        background-color: #313244;
        color: #cdd6f4;
    }
    
    QComboBox QAbstractItemView::item:selected {
        background-color: #45475a;
        color: #89b4fa;
    }
    }

    /* ===== 复选框样式 ===== */
    QCheckBox {
        color: #cdd6f4;
        spacing: 8px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 4px;
        border: 2px solid #45475a;
        background-color: #11111b;
    }
    
    QCheckBox::indicator:checked {
        background-color: #89b4fa;
        border-color: #89b4fa;
    }
    
    QCheckBox::indicator:hover {
        border-color: #89b4fa;
    }

    /* ===== 单选按钮样式 ===== */
    QRadioButton {
        color: #cdd6f4;
        spacing: 8px;
    }
    
    QRadioButton::indicator {
        width: 16px;
        height: 16px;
        border-radius: 9px;
        border: 2px solid #45475a;
        background-color: #11111b;
    }
    
    QRadioButton::indicator:checked {
        border-color: #89b4fa;
        background-color: #11111b;
    }
    
    QRadioButton::indicator:checked::after {
        content: "";
        width: 8px;
        height: 8px;
        border-radius: 4px;
        background-color: #89b4fa;
    }

    /* ===== 进度条样式 ===== */
    QProgressBar {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 6px;
        min-height: 8px;
        max-height: 8px;
        text-align: center;
        color: transparent;
    }
    
    QProgressBar::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #89b4fa, stop:1 #74c7ec);
        border-radius: 6px;
    }
    
    QProgressBar[error="true"]::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #f38ba8, stop:1 #eba0ac);
    }

    /* ===== 滚动条样式 ===== */
    QScrollBar:vertical {
        background-color: transparent;
        width: 8px;
        margin: 0;
    }
    
    QScrollBar::handle:vertical {
        background-color: #45475a;
        border-radius: 4px;
        min-height: 30px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #585b70;
    }
    
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {
        height: 0;
    }
    
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {
        background-color: transparent;
    }
    
    QScrollBar:horizontal {
        background-color: transparent;
        height: 8px;
        margin: 0;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #45475a;
        border-radius: 4px;
        min-width: 30px;
    }
    
    QScrollBar::handle:horizontal:hover {
        background-color: #585b70;
    }
    
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 0;
    }
    
    QScrollBar::add-page:horizontal,
    QScrollBar::sub-page:horizontal {
        background-color: transparent;
    }

    /* ===== 分隔符样式 ===== */
    QSplitter::handle {
        background-color: #313244;
    }
    
    QSplitter::handle:horizontal {
        width: 1px;
    }
    
    QSplitter::handle:vertical {
        height: 1px;
    }

    /* ===== 标签页样式 ===== */
    QTabWidget::pane {
        border: 1px solid #313244;
        border-radius: 8px;
        background-color: #1e1e2e;
        top: -1px;
    }
    
    QTabBar::tab {
        background-color: #181825;
        color: #6c7086;
        border: 1px solid #313244;
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 10px 20px;
        margin-right: 2px;
    }
    
    QTabBar::tab:selected {
        background-color: #1e1e2e;
        color: #89b4fa;
        border-color: #45475a;
        border-bottom: 2px solid #89b4fa;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #313244;
        color: #cdd6f4;
    }

    /* ===== 分组框样式 ===== */
    QGroupBox {
        color: #cdd6f4;
        border: 1px solid #313244;
        border-radius: 8px;
        margin-top: 12px;
        padding: 20px 15px 15px 15px;
        font-weight: bold;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 15px;
        padding: 0 8px;
        color: #89b4fa;
    }

    /* ===== 菜单样式 ===== */
    QMenuBar {
        background-color: #181825;
        color: #cdd6f4;
        border-bottom: 1px solid #313244;
        padding: 4px;
    }
    
    QMenuBar::item {
        padding: 8px 12px;
        border-radius: 4px;
        background-color: transparent;
    }
    
    QMenuBar::item:selected {
        background-color: #313244;
    }
    
    QMenu {
        background-color: #181825;
        border: 1px solid #45475a;
        border-radius: 8px;
        padding: 8px;
    }
    
    QMenu::item {
        padding: 8px 30px 8px 20px;
        border-radius: 4px;
        color: #cdd6f4;
    }
    
    QMenu::item:selected {
        background-color: #45475a;
        color: #cdd6f4;
    }
    
    QMenu::separator {
        height: 1px;
        background-color: #313244;
        margin: 6px 10px;
    }

    /* ===== 工具栏样式 ===== */
    QToolBar {
        background-color: #181825;
        border-bottom: 1px solid #313244;
        spacing: 6px;
        padding: 6px;
    }
    
    QToolBar QToolButton {
        background-color: transparent;
        border: none;
        border-radius: 6px;
        padding: 8px 12px;
        color: #a6adc8;
    }
    
    QToolBar QToolButton:hover {
        background-color: #313244;
        color: #cdd6f4;
    }
    
    QToolBar QToolButton:pressed {
        background-color: #45475a;
    }
    
    QToolBar QToolButton#toolButtonSeparator {
        background-color: #313244;
        width: 1px;
        margin: 4px 6px;
    }

    /* ===== 状态栏样式 ===== */
    QStatusBar {
        background-color: #181825;
        color: #6c7086;
        border-top: 1px solid #313244;
        padding: 4px 10px;
    }
    
    QStatusBar QLabel {
        color: #6c7086;
    }
    
    QStatusBar::item {
        border: none;
    }

    /* ===== 表格样式 ===== */
    QTableWidget, QTableView {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        gridline-color: #313244;
        selection-background-color: #45475a;
        selection-color: #cdd6f4;
        alternate-background-color: #1e1e2e;
    }
    
    QTableWidget::item, QTableView::item {
        padding: 8px;
        color: #cdd6f4;
    }
    
    QHeaderView::section {
        background-color: #181825;
        color: #89b4fa;
        padding: 10px;
        border: none;
        border-bottom: 2px solid #313244;
        font-weight: 600;
    }

    /* ===== 列表视图样式 ===== */
    QListView {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        selection-background-color: #45475a;
        selection-color: #cdd6f4;
        outline: none;
    }
    
    QListView::item {
        padding: 12px;
        border-radius: 6px;
        background-color: transparent;
        color: #cdd6f4;
    }
    
    QListView::item:hover {
        background-color: #313244;
    }
    
    QListView::item:selected {
        background-color: #45475a;
        color: #89b4fa;
    }

    /* ===== 树形视图样式 ===== */
    QTreeView {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        selection-background-color: #45475a;
        selection-color: #cdd6f4;
        outline: none;
        show-decoration-selected: 1;
    }
    
    QTreeView::item {
        padding: 6px;
        color: #cdd6f4;
    }
    
    QTreeView::item:hover {
        background-color: #313244;
    }
    
    QTreeView::item:selected {
        background-color: #45475a;
        color: #89b4fa;
    }

    /* ===== 消息框样式 ===== */
    QMessageBox {
        background-color: #181825;
    }
    
    QMessageBox QLabel {
        color: #cdd6f4;
    }

    /* ===== 对话框样式 ===== */
    QDialog {
        background-color: #1e1e2e;
    }

    /* ===== 旋转框样式 ===== */
    QSpinBox, QDoubleSpinBox {
        background-color: #11111b;
        border: 1px solid #313244;
        border-radius: 8px;
        padding: 8px 12px;
        color: #cdd6f4;
    }
    
    QSpinBox:focus, QDoubleSpinBox:focus {
        border-color: #89b4fa;
    }
    
    QSpinBox::up-button, QDoubleSpinBox::up-button,
    QSpinBox::down-button, QDoubleSpinBox::down-button {
        background-color: transparent;
        border: none;
        width: 20px;
    }
    
    QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
    QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {
        background-color: #313244;
    }

    /* ===== 滑块样式 ===== */
    QSlider::groove:horizontal {
        background-color: #313244;
        height: 6px;
        border-radius: 3px;
    }
    
    QSlider::handle:horizontal {
        background-color: #89b4fa;
        width: 16px;
        height: 16px;
        border-radius: 8px;
        margin: -5px 0;
    }
    
    QSlider::handle:horizontal:hover {
        background-color: #74c7ec;
    }
    
    QSlider::groove:vertical {
        background-color: #313244;
        width: 6px;
        border-radius: 3px;
    }
    
    QSlider::handle:vertical {
        background-color: #89b4fa;
        width: 16px;
        height: 16px;
        border-radius: 8px;
        margin: 0 -5px;
    }

    /* ===== 日志级别颜色 ===== */
    QLabel[level="info"] { color: #89b4fa; }
    QLabel[level="success"] { color: #a6e3a1; }
    QLabel[level="warning"] { color: #f9e2af; }
    QLabel[level="error"] { color: #f38ba8; }
    QLabel[level="debug"] { color: #6c7086; }

    /* ===== 严重性颜色 ===== */
    QLabel[severity="critical"] { 
        color: #f38ba8; 
        font-weight: bold;
        background-color: rgba(243, 139, 168, 0.15);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="high"] { 
        color: #fab387; 
        font-weight: bold;
        background-color: rgba(250, 179, 135, 0.15);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="medium"] { 
        color: #f9e2af; 
        background-color: rgba(249, 226, 175, 0.15);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="low"] { 
        color: #94e2d5; 
        background-color: rgba(148, 226, 213, 0.15);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="info"] { 
        color: #89b4fa; 
        background-color: rgba(137, 180, 250, 0.15);
        padding: 2px 8px;
        border-radius: 4px;
    }
    """

    LIGHT_THEME = """
    /* ===== 全局样式 ===== */
    * {
        font-family: "Microsoft YaHei", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
        font-size: 13px;
        outline: none;
    }
    
    QMainWindow {
        background-color: #eff1f5;
        color: #4c4f69;
    }
    
    QWidget {
        color: #4c4f69;
        background-color: #eff1f5;
    }
    
    QToolTip {
        background-color: #e6e9ef;
        color: #4c4f69;
        border: 1px solid #ccd0da;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 12px;
    }

    /* ===== 侧边栏 ===== */
    QFrame#sidebar {
        background-color: #ffffff;
        border-right: 1px solid #ccd0da;
        min-width: 240px;
        max-width: 280px;
    }

    QLabel#sidebarTitle {
        color: #8839ef;
        font-size: 18px;
        font-weight: bold;
    }
    
    QLabel#sidebarVersion {
        color: #acb0be;
        font-size: 11px;
    }
    
    QLabel#categoryLabel {
        color: #1e66f5;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 1px;
        padding-left: 8px;
        margin-top: 12px;
        margin-bottom: 4px;
    }

    QPushButton#navButton {
        text-align: left;
        padding: 8px 12px;
        border: none;
        border-radius: 6px;
        background: transparent;
        color: #5c5f77;
        min-height: 34px;
    }
    
    QPushButton#navButton:hover {
        background-color: #e6e9ef;
        color: #4c4f69;
    }
    
    QPushButton#navButton:checked {
        background-color: #e6e9ef;
        color: #1e66f5;
        border-left: 3px solid #1e66f5;
    }
    
    QPushButton#navButton[running="true"] {
        background-color: rgba(40, 176, 106, 0.1);
        color: #40a02b;
        border-left: 3px solid #40a02b;
    }

    /* ===== 主内容区 ===== */
    QFrame#mainContent {
        background-color: #eff1f5;
        border: none;
    }

    /* ===== 标题栏 ===== */
    QFrame#titleBar {
        background-color: #ffffff;
        border-bottom: 1px solid #ccd0da;
        min-height: 48px;
    }
    
    QLabel#titleLabel {
        color: #4c4f69;
        font-size: 16px;
        font-weight: 600;
    }
    
    QLabel#projectLabel {
        color: #acb0be;
        font-size: 12px;
    }
    
    QLabel#projectNameLabel {
        color: #1e66f5;
        font-size: 12px;
        font-weight: 500;
    }

    /* ===== 卡片样式 ===== */
    QFrame#card {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 12px;
    }
    
    QFrame#card:hover {
        border-color: #acb0be;
    }

    /* ===== 按钮样式 ===== */
    QPushButton#primaryButton {
        background-color: #1e66f5;
        color: #ffffff;
        border: none;
        border-radius: 4px;
        padding: 6px 16px;
        font-weight: 600;
        font-size: 13px;
    }
    
    QPushButton#primaryButton:hover {
        background-color: #1565c0;
    }
    
    QPushButton#primaryButton:pressed {
        background-color: #1976d2;
    }
    
    QPushButton#primaryButton:disabled {
        background-color: #ccd0da;
        color: #acb0be;
    }
    
    QPushButton#secondaryButton {
        background-color: #ffffff;
        color: #4c4f69;
        border: 1px solid #ccd0da;
        border-radius: 6px;
        padding: 8px 16px;
        text-align: left;
    }
    
    QPushButton#secondaryButton:hover {
        background-color: #e6e9ef;
        border-color: #acb0be;
    }
    
    QPushButton#dangerButton {
        background-color: #d20f39;
        color: #ffffff;
        border: none;
        border-radius: 4px;
        padding: 6px 16px;
        font-weight: 600;
    }
    
    QPushButton#dangerButton:hover {
        background-color: #dc2626;
    }
    
    QPushButton#successButton {
        background-color: #40a02b;
        color: #ffffff;
        border: none;
        border-radius: 8px;
        padding: 10px 24px;
        font-weight: 600;
    }
    
    QPushButton#successButton:hover {
        background-color: #37a44f;
    }

    QPushButton#iconButton {
        background-color: transparent;
        border: 1px solid #ccd0da;
        border-radius: 6px;
        padding: 8px;
        min-width: 36px;
        min-height: 36px;
        color: #5c5f77;
    }
    
    QPushButton#iconButton:hover {
        background-color: #e6e9ef;
        color: #4c4f69;
        border-color: #acb0be;
    }

    /* ===== 输入框样式 ===== */
    QLineEdit {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        padding: 10px 14px;
        color: #4c4f69;
        selection-background-color: #e6e9ef;
        min-height: 20px;
    }
    
    QLineEdit:focus {
        border-color: #1e66f5;
    }
    
    QLineEdit:read-only {
        background-color: #eff1f5;
        color: #acb0be;
    }
    
    QLineEdit::placeholder {
        color: #acb0be;
    }

    QTextEdit {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        color: #4c4f69;
        selection-background-color: #e6e9ef;
        padding: 10px;
    }
    
    QTextEdit:focus {
        border-color: #1e66f5;
    }

    QPlainTextEdit {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        color: #4c4f69;
        selection-background-color: #e6e9ef;
        padding: 10px;
    }
    
    QPlainTextEdit:focus {
        border-color: #1e66f5;
    }

    /* ===== 下拉框样式 ===== */
    QComboBox {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        padding: 10px 14px;
        color: #4c4f69;
        min-height: 20px;
    }
    
    QComboBox:focus {
        border-color: #1e66f5;
    }
    
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 30px;
        border: none;
        border-top-right-radius: 8px;
        border-bottom-right-radius: 8px;
    }
    
    QComboBox::down-arrow {
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid #acb0be;
        margin-right: 10px;
    }
    
    QComboBox QAbstractItemView {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        padding: 4px;
        selection-background-color: #e6e9ef;
        selection-color: #4c4f69;
        outline: none;
        color: #4c4f69;
    }
    
    QComboBox QAbstractItemView::item {
        padding: 8px 12px;
        min-height: 28px;
        border-radius: 4px;
        color: #4c4f69;
    }
    
    QComboBox QAbstractItemView::item:hover {
        background-color: #e6e9ef;
        color: #4c4f69;
    }
    
    QComboBox QAbstractItemView::item:selected {
        background-color: #e6e9ef;
        color: #1e66f5;
    }

    /* ===== 复选框样式 ===== */
    QCheckBox {
        color: #4c4f69;
        spacing: 8px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 4px;
        border: 2px solid #ccd0da;
        background-color: #ffffff;
    }
    
    QCheckBox::indicator:checked {
        background-color: #1e66f5;
        border-color: #1e66f5;
    }
    
    QCheckBox::indicator:hover {
        border-color: #1e66f5;
    }

    /* ===== 单选按钮样式 ===== */
    QRadioButton {
        color: #4c4f69;
        spacing: 8px;
    }
    
    QRadioButton::indicator {
        width: 16px;
        height: 16px;
        border-radius: 9px;
        border: 2px solid #ccd0da;
        background-color: #ffffff;
    }
    
    QRadioButton::indicator:checked {
        border-color: #1e66f5;
        background-color: #ffffff;
    }

    /* ===== 进度条样式 ===== */
    QProgressBar {
        background-color: #e6e9ef;
        border: 1px solid #ccd0da;
        border-radius: 6px;
        min-height: 8px;
        max-height: 8px;
        text-align: center;
        color: transparent;
    }
    
    QProgressBar::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #1e66f5, stop:1 #1565c0);
        border-radius: 6px;
    }
    
    QProgressBar[error="true"]::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #d20f39, stop:1 #dc2626);
    }

    /* ===== 滚动条样式 ===== */
    QScrollBar:vertical {
        background-color: transparent;
        width: 8px;
        margin: 0;
    }
    
    QScrollBar::handle:vertical {
        background-color: #ccd0da;
        border-radius: 4px;
        min-height: 30px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #acb0be;
    }
    
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {
        height: 0;
    }
    
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {
        background-color: transparent;
    }
    
    QScrollBar:horizontal {
        background-color: transparent;
        height: 8px;
        margin: 0;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #ccd0da;
        border-radius: 4px;
        min-width: 30px;
    }
    
    QScrollBar::handle:horizontal:hover {
        background-color: #acb0be;
    }
    
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 0;
    }
    
    QScrollBar::add-page:horizontal,
    QScrollBar::sub-page:horizontal {
        background-color: transparent;
    }

    /* ===== 分隔符样式 ===== */
    QSplitter::handle {
        background-color: #ccd0da;
    }
    
    QSplitter::handle:horizontal {
        width: 1px;
    }
    
    QSplitter::handle:vertical {
        height: 1px;
    }

    /* ===== 标签页样式 ===== */
    QTabWidget::pane {
        border: 1px solid #ccd0da;
        border-radius: 8px;
        background-color: #eff1f5;
        top: -1px;
    }
    
    QTabBar::tab {
        background-color: #ffffff;
        color: #acb0be;
        border: 1px solid #ccd0da;
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 10px 20px;
        margin-right: 2px;
    }
    
    QTabBar::tab:selected {
        background-color: #eff1f5;
        color: #1e66f5;
        border-color: #ccd0da;
        border-bottom: 2px solid #1e66f5;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #e6e9ef;
        color: #4c4f69;
    }

    /* ===== 分组框样式 ===== */
    QGroupBox {
        color: #4c4f69;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        margin-top: 12px;
        padding: 20px 15px 15px 15px;
        font-weight: bold;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 15px;
        padding: 0 8px;
        color: #1e66f5;
    }

    /* ===== 菜单样式 ===== */
    QMenuBar {
        background-color: #ffffff;
        color: #4c4f69;
        border-bottom: 1px solid #ccd0da;
        padding: 4px;
    }
    
    QMenuBar::item {
        padding: 8px 12px;
        border-radius: 4px;
        background-color: transparent;
    }
    
    QMenuBar::item:selected {
        background-color: #e6e9ef;
    }
    
    QMenu {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        padding: 8px;
    }
    
    QMenu::item {
        padding: 8px 30px 8px 20px;
        border-radius: 4px;
        color: #4c4f69;
    }
    
    QMenu::item:selected {
        background-color: #e6e9ef;
        color: #4c4f69;
    }
    
    QMenu::separator {
        height: 1px;
        background-color: #ccd0da;
        margin: 6px 10px;
    }

    /* ===== 工具栏样式 ===== */
    QToolBar {
        background-color: #ffffff;
        border-bottom: 1px solid #ccd0da;
        spacing: 6px;
        padding: 6px;
    }
    
    QToolBar QToolButton {
        background-color: transparent;
        border: none;
        border-radius: 6px;
        padding: 8px 12px;
        color: #5c5f77;
    }
    
    QToolBar QToolButton:hover {
        background-color: #e6e9ef;
        color: #4c4f69;
    }
    
    QToolBar QToolButton:pressed {
        background-color: #ccd0da;
    }

    /* ===== 状态栏样式 ===== */
    QStatusBar {
        background-color: #ffffff;
        color: #acb0be;
        border-top: 1px solid #ccd0da;
        padding: 4px 10px;
    }
    
    QStatusBar QLabel {
        color: #acb0be;
    }
    
    QStatusBar::item {
        border: none;
    }

    /* ===== 表格样式 ===== */
    QTableWidget, QTableView {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        gridline-color: #e6e9ef;
        selection-background-color: #e6e9ef;
        selection-color: #4c4f69;
        alternate-background-color: #f5f7fa;
    }
    
    QTableWidget::item, QTableView::item {
        padding: 8px;
        color: #4c4f69;
    }
    
    QHeaderView::section {
        background-color: #eff1f5;
        color: #1e66f5;
        padding: 10px;
        border: none;
        border-bottom: 2px solid #ccd0da;
        font-weight: 600;
    }

    /* ===== 列表视图样式 ===== */
    QListView {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        selection-background-color: #e6e9ef;
        selection-color: #4c4f69;
        outline: none;
    }
    
    QListView::item {
        padding: 12px;
        border-radius: 6px;
        background-color: transparent;
        color: #4c4f69;
    }
    
    QListView::item:hover {
        background-color: #e6e9ef;
    }
    
    QListView::item:selected {
        background-color: #e6e9ef;
        color: #1e66f5;
    }

    /* ===== 树形视图样式 ===== */
    QTreeView {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        selection-background-color: #e6e9ef;
        selection-color: #4c4f69;
        outline: none;
        show-decoration-selected: 1;
    }
    
    QTreeView::item {
        padding: 6px;
        color: #4c4f69;
    }
    
    QTreeView::item:hover {
        background-color: #e6e9ef;
    }
    
    QTreeView::item:selected {
        background-color: #e6e9ef;
        color: #1e66f5;
    }

    /* ===== 消息框样式 ===== */
    QMessageBox {
        background-color: #ffffff;
    }
    
    QMessageBox QLabel {
        color: #4c4f69;
    }

    /* ===== 对话框样式 ===== */
    QDialog {
        background-color: #eff1f5;
    }

    /* ===== 旋转框样式 ===== */
    QSpinBox, QDoubleSpinBox {
        background-color: #ffffff;
        border: 1px solid #ccd0da;
        border-radius: 8px;
        padding: 8px 12px;
        color: #4c4f69;
    }
    
    QSpinBox:focus, QDoubleSpinBox:focus {
        border-color: #1e66f5;
    }
    
    QSpinBox::up-button, QDoubleSpinBox::up-button,
    QSpinBox::down-button, QDoubleSpinBox::down-button {
        background-color: transparent;
        border: none;
        width: 20px;
    }
    
    QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
    QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {
        background-color: #e6e9ef;
    }

    /* ===== 滑块样式 ===== */
    QSlider::groove:horizontal {
        background-color: #ccd0da;
        height: 6px;
        border-radius: 3px;
    }
    
    QSlider::handle:horizontal {
        background-color: #1e66f5;
        width: 16px;
        height: 16px;
        border-radius: 8px;
        margin: -5px 0;
    }
    
    QSlider::handle:horizontal:hover {
        background-color: #1565c0;
    }

    /* ===== 日志级别颜色 ===== */
    QLabel[level="info"] { color: #1e66f5; }
    QLabel[level="success"] { color: #40a02b; }
    QLabel[level="warning"] { color: #df8e1d; }
    QLabel[level="error"] { color: #d20f39; }
    QLabel[level="debug"] { color: #acb0be; }

    /* ===== 严重性颜色 ===== */
    QLabel[severity="critical"] { 
        color: #d20f39; 
        font-weight: bold;
        background-color: rgba(210, 15, 57, 0.1);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="high"] { 
        color: #fe640b; 
        font-weight: bold;
        background-color: rgba(254, 100, 11, 0.1);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="medium"] { 
        color: #df8e1d; 
        background-color: rgba(223, 142, 29, 0.1);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="low"] { 
        color: #179299; 
        background-color: rgba(23, 146, 153, 0.1);
        padding: 2px 8px;
        border-radius: 4px;
    }
    QLabel[severity="info"] { 
        color: #1e66f5; 
        background-color: rgba(30, 102, 245, 0.1);
        padding: 2px 8px;
        border-radius: 4px;
    }
    """
    
    @classmethod
    def get_theme(cls, dark=True) -> str:
        return cls.DARK_THEME if dark else cls.LIGHT_THEME
