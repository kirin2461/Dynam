#pragma once

#include <QWidget>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>

namespace widgets {

/**
 * @brief Application settings widget (language, theme).
 */
class SettingsWidget : public QWidget {
    Q_OBJECT

public:
    explicit SettingsWidget(QWidget* parent = nullptr);

signals:
    void languageChanged(const QString& lang);
    void themeChanged(const QString& theme);

private slots:
    void onLanguageChanged(int index);
    void onThemeChanged(int index);

private:
    void setupUi();
    
    QComboBox* m_languageCombo;
    QComboBox* m_themeCombo;
};

} // namespace widgets
