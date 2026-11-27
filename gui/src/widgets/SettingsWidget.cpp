#include "SettingsWidget.hpp"

#include <QGroupBox>
#include <QFormLayout>
#include <QFont>
#include <QSettings>

namespace widgets {

SettingsWidget::SettingsWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void SettingsWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(16);
    
    // ─── Title ─────────────────────────────────────────────────────────
    auto* titleLabel = new QLabel(tr("Application Settings"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);
    
    // ─── Appearance ────────────────────────────────────────────────────
    auto* appearanceGroup = new QGroupBox(tr("Appearance"));
    auto* appearanceLayout = new QFormLayout(appearanceGroup);
    appearanceLayout->setSpacing(12);
    
    m_languageCombo = new QComboBox();
    m_languageCombo->addItem("Русский", "ru");
    m_languageCombo->addItem("English", "en");
    
    // Load saved language
    QSettings settings;
    QString savedLang = settings.value("language", "ru").toString();
    for (int i = 0; i < m_languageCombo->count(); ++i) {
        if (m_languageCombo->itemData(i).toString() == savedLang) {
            m_languageCombo->setCurrentIndex(i);
            break;
        }
    }
    
    connect(m_languageCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SettingsWidget::onLanguageChanged);
    appearanceLayout->addRow(tr("Language:"), m_languageCombo);
    
    m_themeCombo = new QComboBox();
    m_themeCombo->addItem(tr("Dark"), "dark");
    m_themeCombo->addItem(tr("Light"), "light");
    
    // Load saved theme
    QString savedTheme = settings.value("theme", "dark").toString();
    for (int i = 0; i < m_themeCombo->count(); ++i) {
        if (m_themeCombo->itemData(i).toString() == savedTheme) {
            m_themeCombo->setCurrentIndex(i);
            break;
        }
    }
    
    connect(m_themeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SettingsWidget::onThemeChanged);
    appearanceLayout->addRow(tr("Theme:"), m_themeCombo);
    
    mainLayout->addWidget(appearanceGroup);
    
    mainLayout->addStretch();
}

void SettingsWidget::onLanguageChanged(int index)
{
    QString lang = m_languageCombo->itemData(index).toString();
    emit languageChanged(lang);
}

void SettingsWidget::onThemeChanged(int index)
{
    QString theme = m_themeCombo->itemData(index).toString();
    emit themeChanged(theme);
}

} // namespace widgets
