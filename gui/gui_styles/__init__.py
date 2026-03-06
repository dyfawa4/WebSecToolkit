class StyleSheet:
    THEME = """
    /* 全局样式 */
    * {
        font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
        font-size: 13px;
    }
    
    QWidget {
        color: #1F2937;
        background-color: #F9FAFB;
    }
    
    QMainWindow {
        background-color: #F9FAFB;
    }
    
    /* 侧边栏 */
    QFrame#sidebar {
        background-color: #FFFFFF;
        border-right: 1px solid #E5E7EB;
        min-width: 230px;
        max-width: 290px;
    }
    
    /* 主内容区 */
    QFrame#mainContent {
        background-color: #F9FAFB;
        border: none;
    }
    
    /* 标题栏 */
    QFrame#titleBar {
        background-color: #FFFFFF;
        border-bottom: 1px solid #E5E7EB;
        min-height: 56px;
        max-height: 56px;
    }
    
    QLabel#titleLabel {
        font-size: 19px;
        font-weight: 600;
        color: #111827;
        padding-left: 20px;
        background-color: transparent;
    }
    
    /* 导航按钮 */
    QPushButton#navButton {
        background-color: transparent;
        border: none;
        border-radius: 10px;
        padding: 14px 20px;
        text-align: left;
        font-size: 14px;
        color: #6B7280;
    }
    
    QPushButton#navButton:hover {
        background-color: rgba(0, 0, 0, 0.05);
        color: #111827;
    }
    
    QPushButton#navButton:checked {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #667EEA, stop:1 #764BA2);
        color: #FFFFFF;
        font-weight: 600;
    }
    
    /* 分类标题 */
    QLabel#categoryLabel {
        font-size: 11px;
        font-weight: 600;
        color: #9CA3AF;
        padding: 20px 20px 10px 20px;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        background-color: transparent;
    }
    
    /* 输入框 */
    QLineEdit {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 8px;
        padding: 10px 14px;
        color: #1F2937;
        selection-background-color: #4285F4;
    }
    
    QLineEdit:hover {
        border-color: #9CA3AF;
    }
    
    QLineEdit:focus {
        border-color: #4285F4;
        background-color: #FFFFFF;
    }
    
    QLineEdit:disabled {
        background-color: #F3F4F6;
        color: #9CA3AF;
    }
    
    /* 文本编辑框 */
    QTextEdit {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 8px;
        padding: 10px;
        color: #1F2937;
        selection-background-color: #4285F4;
    }
    
    QTextEdit:focus {
        border-color: #4285F4;
    }
    
    /* 下拉框 */
    QComboBox {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 8px;
        padding: 10px 14px;
        color: #1F2937;
        min-width: 120px;
    }
    
    QComboBox:hover {
        border-color: #9CA3AF;
    }
    
    QComboBox:focus, QComboBox:on {
        border-color: #4285F4;
    }
    
    QComboBox::drop-down {
        border: none;
        width: 0px;
        background: transparent;
    }
    
    QComboBox::down-arrow {
        image: none;
        width: 0px;
        height: 0px;
    }
    
    QComboBox QAbstractItemView {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 4px;
        selection-background-color: #667EEA;
        selection-color: #FFFFFF;
        outline: none;
        padding: 2px;
    }
    
    QComboBox QAbstractItemView::item {
        background-color: transparent;
        color: #374151;
        padding: 6px 10px;
        min-height: 24px;
        border: none;
    }
    
    QComboBox QAbstractItemView::item:hover {
        background-color: #F3F4F6;
    }
    
    QComboBox QAbstractItemView::item:selected {
        background-color: #667EEA;
        color: #FFFFFF;
    }
    
    /* 主按钮 */
    QPushButton {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #667EEA, stop:1 #764BA2);
        border: none;
        border-radius: 8px;
        padding: 11px 24px;
        color: #FFFFFF;
        font-weight: 600;
        min-width: 90px;
    }
    
    QPushButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #768FEB, stop:1 #865BA3);
    }
    
    QPushButton:pressed {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #5A6FD6, stop:1 #6A4A91);
    }
    
    QPushButton:disabled {
        background: #D1D5DB;
        color: #9CA3AF;
    }
    
    /* 次要按钮 */
    QPushButton#secondaryButton {
        background: #FFFFFF;
        border: 1px solid #D1D5DB;
        color: #374151;
    }
    
    QPushButton#secondaryButton:hover {
        background: #F9FAFB;
        border-color: #9CA3AF;
    }
    
    QPushButton#secondaryButton:pressed {
        background: #F3F4F6;
    }
    
    /* 危险按钮 */
    QPushButton#dangerButton {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #EF4444, stop:1 #DC2626);
    }
    
    QPushButton#dangerButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #F87171, stop:1 #EF4444);
    }
    
    /* 分组框 */
    QGroupBox {
        background-color: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        margin-top: 12px;
        padding: 16px;
        padding-top: 24px;
        font-weight: 600;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 8px;
        color: #374151;
        background-color: #FFFFFF;
        border-radius: 4px;
    }
    
    /* 滚动条 */
    QScrollBar:vertical {
        background-color: #F3F4F6;
        width: 10px;
        margin: 0;
        border-radius: 5px;
    }
    
    QScrollBar::handle:vertical {
        background-color: #D1D5DB;
        border-radius: 5px;
        min-height: 30px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #9CA3AF;
    }
    
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {
        height: 0px;
    }
    
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {
        background: none;
    }
    
    QScrollBar:horizontal {
        background-color: #F3F4F6;
        height: 10px;
        margin: 0;
        border-radius: 5px;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #D1D5DB;
        border-radius: 5px;
        min-width: 30px;
    }
    
    QScrollBar::handle:horizontal:hover {
        background-color: #9CA3AF;
    }
    
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 0px;
    }
    
    QScrollBar::add-page:horizontal,
    QScrollBar::sub-page:horizontal {
        background: none;
    }
    
    /* 表格 */
    QTableWidget {
        background-color: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        gridline-color: #E5E7EB;
        selection-background-color: #4285F4;
        selection-color: #FFFFFF;
        outline: none;
    }
    
    QTableWidget::item {
        padding: 8px;
        border-bottom: 1px solid #E5E7EB;
    }
    
    QTableWidget::item:selected {
        background-color: #4285F4;
        color: #FFFFFF;
    }
    
    QHeaderView::section {
        background-color: #F9FAFB;
        color: #6B7280;
        padding: 10px;
        border: none;
        border-bottom: 1px solid #E5E7EB;
        font-weight: 600;
    }
    
    QHeaderView::section:horizontal {
        border-right: 1px solid #E5E7EB;
    }
    
    QHeaderView::section:last:horizontal {
        border-right: none;
    }
    
    /* 复选框 */
    QCheckBox {
        spacing: 8px;
        color: #374151;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 4px;
        border: 2px solid #D1D5DB;
        background-color: #FFFFFF;
    }
    
    QCheckBox::indicator:hover {
        border-color: #9CA3AF;
    }
    
    QCheckBox::indicator:checked {
        background-color: #4285F4;
        border-color: #4285F4;
    }
    
    QCheckBox::indicator:disabled {
        background-color: #F3F4F6;
        border-color: #E5E7EB;
    }
    
    /* 单选按钮 */
    QRadioButton {
        spacing: 8px;
        color: #374151;
    }
    
    QRadioButton::indicator {
        width: 18px;
        height: 18px;
        border-radius: 9px;
        border: 2px solid #D1D5DB;
        background-color: #FFFFFF;
    }
    
    QRadioButton::indicator:hover {
        border-color: #9CA3AF;
    }
    
    QRadioButton::indicator:checked {
        background-color: #FFFFFF;
        border: 6px solid #4285F4;
    }
    
    /* 进度条 */
    QProgressBar {
        background-color: #E5E7EB;
        border: none;
        border-radius: 4px;
        text-align: center;
        color: #374151;
        font-weight: 600;
    }
    
    QProgressBar::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #667EEA, stop:1 #764BA2);
        border-radius: 4px;
    }
    
    /* TabWidget */
    QTabWidget::pane {
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        background-color: #FFFFFF;
    }
    
    QTabBar::tab {
        background-color: #F3F4F6;
        color: #6B7280;
        padding: 10px 20px;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        margin-right: 2px;
    }
    
    QTabBar::tab:selected {
        background-color: #FFFFFF;
        color: #4285F4;
        border: 1px solid #E5E7EB;
        border-bottom: none;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #E5E7EB;
        color: #374151;
    }
    
    /* 分割器 */
    QSplitter::handle {
        background-color: #E5E7EB;
    }
    
    QSplitter::handle:horizontal {
        width: 4px;
    }
    
    QSplitter::handle:vertical {
        height: 4px;
    }
    
    QSplitter::handle:hover {
        background-color: #D1D5DB;
    }
    
    /* SpinBox */
    QSpinBox {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 8px;
        padding: 10px 14px;
        color: #1F2937;
    }
    
    QSpinBox:hover {
        border-color: #9CA3AF;
    }
    
    QSpinBox:focus {
        border-color: #4285F4;
    }
    
    QSpinBox::up-button {
        subcontrol-origin: border;
        subcontrol-position: right;
        width: 0px;
        border: none;
        background-color: transparent;
    }
    
    QSpinBox::down-button {
        subcontrol-origin: border;
        subcontrol-position: right;
        width: 0px;
        border: none;
        background-color: transparent;
    }
    
    QSpinBox::up-arrow {
        image: none;
        width: 0px;
        height: 0px;
    }
    
    QSpinBox::down-arrow {
        image: none;
        width: 0px;
        height: 0px;
    }
    
    /* DateEdit */
    QDateEdit {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 8px;
        padding: 10px 14px;
        color: #1F2937;
    }
    
    QDateEdit:hover {
        border-color: #9CA3AF;
    }
    
    QDateEdit:focus {
        border-color: #4285F4;
    }
    
    QDateEdit::drop-down {
        border: none;
        width: 0px;
    }
    
    QDateEdit::down-arrow {
        image: none;
        width: 0px;
        height: 0px;
    }
    
    /* 普通标签背景透明 */
    QLabel {
        background-color: transparent;
        color: #1F2937;
    }
    
    /* 工具栏 */
    QToolBar {
        background-color: #FFFFFF;
        border-bottom: 1px solid #E5E7EB;
        padding: 8px 12px;
        spacing: 8px;
    }
    
    QToolBar QToolButton {
        background-color: transparent;
        color: #6B7280;
        border: none;
        border-radius: 6px;
        padding: 10px 14px;
    }
    
    QToolBar QToolButton:hover {
        background-color: #F3F4F6;
        color: #1F2937;
    }
    
    QToolBar QToolButton:pressed {
        background-color: #E5E7EB;
    }
    
    /* 菜单栏 */
    QMenuBar {
        background-color: #FFFFFF;
        color: #1F2937;
        padding: 0;
        border-bottom: 1px solid #E5E7EB;
    }
    
    QMenuBar::item {
        background-color: transparent;
        padding: 10px 16px;
        border-radius: 6px;
        margin: 2px;
    }
    
    QMenuBar::item:selected {
        background-color: #F3F4F6;
    }
    
    QMenuBar::item:pressed {
        background-color: #E5E7EB;
    }
    
    /* 统计卡片 */
    QFrame#statCard {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #FFFFFF, stop:1 #F9FAFB);
        border: 1px solid #E5E7EB;
        border-radius: 16px;
        padding: 0;
        margin: 0;
    }
    
    QLabel#statNumber {
        font-size: 36px;
        font-weight: 700;
        color: #4285F4;
        background-color: transparent;
        border: none;
    }
    
    QLabel#statLabel {
        font-size: 14px;
        color: #6B7280;
        background-color: transparent;
        border: none;
    }
    
    /* 日志显示 */
    QTextEdit#logView {
        font-family: "Consolas", "Monaco", "Courier New", monospace;
        font-size: 12px;
        background-color: #F9FAFB;
        color: #1F2937;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
    }
    
    /* 卡片 */
    QFrame#card {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #FFFFFF, stop:1 #F9FAFB);
        border: 1px solid #E5E7EB;
        border-radius: 12px;
        padding: 20px;
    }
    
    /* 列表视图 */
    QListView {
        background-color: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        selection-background-color: #4285F4;
        selection-color: #FFFFFF;
        outline: none;
    }
    
    QListView::item {
        padding: 12px;
        border-radius: 6px;
        background-color: transparent;
        color: #1F2937;
    }
    
    QListView::item:hover {
        background-color: #F3F4F6;
    }
    
    QListView::item:selected {
        background-color: #4285F4;
        color: #FFFFFF;
    }
    """
    
    @classmethod
    def get_theme(cls) -> str:
        return cls.THEME
