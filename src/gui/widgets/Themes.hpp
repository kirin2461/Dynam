#pragma once
#include <QString>
#include <QApplication>
#include <QSettings>

// Three themes: "system" (no stylesheet, use OS default), "dark", "light".
// Persisted under ui/theme. apply() reads QSettings and sets qApp's
// stylesheet to match — call once at startup and again whenever Settings
// changes.
namespace Themes {

inline QString darkQss() {
    return QStringLiteral(R"(
        QMainWindow, QDialog { background: #1f1f2e; color: #e0e0e0; }
        QWidget   { color: #e0e0e0; }
        QGroupBox { border: 1px solid #3a3a4a; border-radius: 6px;
                    margin-top: 12px; padding-top: 12px; }
        QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px;
                           color: #a0a0c0; }
        QTabBar::tab { background: #2a2a3a; color: #c0c0d0;
                       padding: 8px 16px; border-top-left-radius: 4px;
                       border-top-right-radius: 4px; }
        QTabBar::tab:selected { background: #3a3a55; color: #ffffff; }
        QPushButton { background: #3a3a55; border: 1px solid #4a4a65;
                      padding: 6px 14px; border-radius: 4px; }
        QPushButton:hover    { background: #45456b; }
        QPushButton:pressed  { background: #2f2f48; }
        QPushButton:disabled { background: #28283a; color: #666; }
        QLineEdit, QPlainTextEdit, QComboBox, QSpinBox, QTreeWidget, QListWidget {
            background: #161620; color: #e0e0e0;
            border: 1px solid #3a3a4a; border-radius: 3px; padding: 3px;
        }
        QHeaderView::section { background: #2a2a3a; color: #c0c0d0;
                               border: 0; padding: 4px; }
        QStatusBar { background: #161620; color: #b0b0c0; }
        QMenuBar      { background: #1f1f2e; color: #d0d0e0; }
        QMenuBar::item:selected { background: #3a3a55; }
        QMenu         { background: #2a2a3a; color: #d0d0e0; }
        QMenu::item:selected { background: #3a3a55; }
    )");
}

inline QString lightQss() {
    return QStringLiteral(R"(
        QMainWindow, QDialog { background: #f5f5f8; color: #222; }
        QGroupBox { border: 1px solid #d0d0d8; border-radius: 6px;
                    margin-top: 12px; padding-top: 12px; }
        QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px;
                           color: #555; }
        QPushButton { background: #ffffff; border: 1px solid #d0d0d8;
                      padding: 6px 14px; border-radius: 4px; }
        QPushButton:hover   { background: #f0f0f5; }
        QPushButton:pressed { background: #e0e0e8; }
    )");
}

inline void apply() {
    const QString name = QSettings().value("ui/theme", "system").toString();
    if      (name == "dark")  qApp->setStyleSheet(darkQss());
    else if (name == "light") qApp->setStyleSheet(lightQss());
    else                       qApp->setStyleSheet("");  // system
}

} // namespace Themes
