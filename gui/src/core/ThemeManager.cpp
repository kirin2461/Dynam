#include "ThemeManager.hpp"

#include <QApplication>
#include <QSettings>

namespace core {

ThemeManager& ThemeManager::instance()
{
    static ThemeManager inst;
    return inst;
}

ThemeManager::ThemeManager(QObject* parent)
    : QObject(parent)
{
}

ThemeManager::~ThemeManager() = default;

void ThemeManager::setTheme(const QString& theme)
{
    QString normalized = theme.toLower();
    if (normalized != m_currentTheme) {
        m_currentTheme = normalized;
        
        // Apply stylesheet
        QString stylesheet = currentStylesheet();
        qApp->setStyleSheet(stylesheet);
        
        // Persist
        QSettings settings;
        settings.setValue("theme", m_currentTheme);
        
        emit themeChanged(m_currentTheme);
    }
}

QStringList ThemeManager::availableThemes() const
{
    return {"dark", "light"};
}

QString ThemeManager::currentStylesheet() const
{
    if (m_currentTheme == "light") {
        return getLightStylesheet();
    }
    return getDarkStylesheet();
}

QString ThemeManager::getDarkStylesheet() const
{
    return R"(
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
            font-size: 10pt;
        }
        
        QMainWindow {
            background-color: #1e1e2e;
        }
        
        QTabWidget::pane {
            border: 1px solid #45475a;
            background-color: #1e1e2e;
        }
        
        QTabBar::tab {
            background-color: #313244;
            color: #a6adc8;
            padding: 10px 20px;
            border: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
        }
        
        QTabBar::tab:selected {
            background-color: #45475a;
            color: #89b4fa;
        }
        
        QTabBar::tab:hover {
            background-color: #585b70;
        }
        
        QPushButton {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 500;
        }
        
        QPushButton:hover {
            background-color: #45475a;
            border-color: #585b70;
        }
        
        QPushButton:pressed {
            background-color: #585b70;
        }
        
        QPushButton:disabled {
            background-color: #1e1e2e;
            color: #585b70;
            border-color: #313244;
        }
        
        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            padding: 6px;
            border-radius: 4px;
        }
        
        QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
            border-color: #89b4fa;
        }
        
        QComboBox::drop-down {
            border: none;
            width: 24px;
        }
        
        QComboBox QAbstractItemView {
            background-color: #313244;
            color: #cdd6f4;
            selection-background-color: #45475a;
            selection-color: #89b4fa;
            border: 1px solid #45475a;
        }
        
        QTableWidget, QTableView {
            background-color: #1e1e2e;
            alternate-background-color: #181825;
            color: #cdd6f4;
            gridline-color: #313244;
            border: 1px solid #45475a;
        }
        
        QHeaderView::section {
            background-color: #313244;
            color: #cdd6f4;
            padding: 6px;
            border: none;
            border-right: 1px solid #45475a;
            border-bottom: 1px solid #45475a;
            font-weight: 600;
        }
        
        QScrollBar:vertical {
            background-color: #1e1e2e;
            width: 12px;
            margin: 0;
        }
        
        QScrollBar::handle:vertical {
            background-color: #45475a;
            min-height: 20px;
            border-radius: 6px;
            margin: 2px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #585b70;
        }
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        
        QScrollBar:horizontal {
            background-color: #1e1e2e;
            height: 12px;
        }
        
        QScrollBar::handle:horizontal {
            background-color: #45475a;
            min-width: 20px;
            border-radius: 6px;
            margin: 2px;
        }
        
        QScrollBar::handle:horizontal:hover {
            background-color: #585b70;
        }
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
        
        QTextEdit, QPlainTextEdit {
            background-color: #181825;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 4px;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 9pt;
        }
        
        QGroupBox {
            border: 1px solid #45475a;
            border-radius: 6px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: 600;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #89b4fa;
        }
        
        QCheckBox {
            spacing: 8px;
        }
        
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border: 2px solid #45475a;
            border-radius: 3px;
            background-color: #313244;
        }
        
        QCheckBox::indicator:checked {
            background-color: #89b4fa;
            border-color: #89b4fa;
            image: url(:/icons/check.svg);
        }
        
        QCheckBox::indicator:hover {
            border-color: #89b4fa;
        }
        
        QStatusBar {
            background-color: #181825;
            color: #a6adc8;
            border-top: 1px solid #313244;
        }
        
        QMenuBar {
            background-color: #1e1e2e;
            color: #cdd6f4;
        }
        
        QMenuBar::item:selected {
            background-color: #313244;
        }
        
        QMenu {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
        }
        
        QMenu::item:selected {
            background-color: #45475a;
            color: #89b4fa;
        }
        
        QToolBar {
            background-color: #1e1e2e;
            border: none;
            spacing: 8px;
            padding: 4px;
        }
        
        QToolTip {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            padding: 4px;
        }
    )";
}

QString ThemeManager::getLightStylesheet() const
{
    return R"(
        QWidget {
            background-color: #eff1f5;
            color: #4c4f69;
            font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
            font-size: 10pt;
        }
        
        QMainWindow {
            background-color: #eff1f5;
        }
        
        QTabWidget::pane {
            border: 1px solid #ccd0da;
            background-color: #eff1f5;
        }
        
        QTabBar::tab {
            background-color: #e6e9ef;
            color: #6c6f85;
            padding: 10px 20px;
            border: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
        }
        
        QTabBar::tab:selected {
            background-color: #ccd0da;
            color: #1e66f5;
        }
        
        QTabBar::tab:hover {
            background-color: #bcc0cc;
        }
        
        QPushButton {
            background-color: #e6e9ef;
            color: #4c4f69;
            border: 1px solid #ccd0da;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 500;
        }
        
        QPushButton:hover {
            background-color: #ccd0da;
            border-color: #bcc0cc;
        }
        
        QPushButton:pressed {
            background-color: #bcc0cc;
        }
        
        QPushButton:disabled {
            background-color: #eff1f5;
            color: #9ca0b0;
            border-color: #e6e9ef;
        }
        
        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
            background-color: #ffffff;
            color: #4c4f69;
            border: 1px solid #ccd0da;
            padding: 6px;
            border-radius: 4px;
        }
        
        QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
            border-color: #1e66f5;
        }
        
        QComboBox::drop-down {
            border: none;
            width: 24px;
        }
        
        QComboBox QAbstractItemView {
            background-color: #ffffff;
            color: #4c4f69;
            selection-background-color: #e6e9ef;
            selection-color: #1e66f5;
            border: 1px solid #ccd0da;
        }
        
        QTableWidget, QTableView {
            background-color: #ffffff;
            alternate-background-color: #f8f9fc;
            color: #4c4f69;
            gridline-color: #e6e9ef;
            border: 1px solid #ccd0da;
        }
        
        QHeaderView::section {
            background-color: #e6e9ef;
            color: #4c4f69;
            padding: 6px;
            border: none;
            border-right: 1px solid #ccd0da;
            border-bottom: 1px solid #ccd0da;
            font-weight: 600;
        }
        
        QScrollBar:vertical {
            background-color: #eff1f5;
            width: 12px;
            margin: 0;
        }
        
        QScrollBar::handle:vertical {
            background-color: #ccd0da;
            min-height: 20px;
            border-radius: 6px;
            margin: 2px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #bcc0cc;
        }
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        
        QScrollBar:horizontal {
            background-color: #eff1f5;
            height: 12px;
        }
        
        QScrollBar::handle:horizontal {
            background-color: #ccd0da;
            min-width: 20px;
            border-radius: 6px;
            margin: 2px;
        }
        
        QScrollBar::handle:horizontal:hover {
            background-color: #bcc0cc;
        }
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
        
        QTextEdit, QPlainTextEdit {
            background-color: #ffffff;
            color: #4c4f69;
            border: 1px solid #ccd0da;
            border-radius: 4px;
            padding: 4px;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 9pt;
        }
        
        QGroupBox {
            border: 1px solid #ccd0da;
            border-radius: 6px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: 600;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #1e66f5;
        }
        
        QCheckBox {
            spacing: 8px;
        }
        
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border: 2px solid #ccd0da;
            border-radius: 3px;
            background-color: #ffffff;
        }
        
        QCheckBox::indicator:checked {
            background-color: #1e66f5;
            border-color: #1e66f5;
            image: url(:/icons/check.svg);
        }
        
        QCheckBox::indicator:hover {
            border-color: #1e66f5;
        }
        
        QStatusBar {
            background-color: #e6e9ef;
            color: #6c6f85;
            border-top: 1px solid #ccd0da;
        }
        
        QMenuBar {
            background-color: #eff1f5;
            color: #4c4f69;
        }
        
        QMenuBar::item:selected {
            background-color: #e6e9ef;
        }
        
        QMenu {
            background-color: #ffffff;
            color: #4c4f69;
            border: 1px solid #ccd0da;
        }
        
        QMenu::item:selected {
            background-color: #e6e9ef;
            color: #1e66f5;
        }
        
        QToolBar {
            background-color: #eff1f5;
            border: none;
            spacing: 8px;
            padding: 4px;
        }
        
        QToolTip {
            background-color: #ffffff;
            color: #4c4f69;
            border: 1px solid #ccd0da;
            padding: 4px;
        }
    )";
}

} // namespace core
