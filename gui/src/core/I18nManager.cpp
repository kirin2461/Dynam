#include "I18nManager.hpp"

#include <QApplication>
#include <QLocale>
#include <QSettings>
#include <QDir>

namespace core {

I18nManager& I18nManager::instance()
{
    static I18nManager inst;
    return inst;
}

I18nManager::I18nManager(QObject* parent)
    : QObject(parent)
    , m_translator(std::make_unique<QTranslator>())
{
}

I18nManager::~I18nManager() = default;

void I18nManager::setLanguage(const QString& lang)
{
    QString normalized = lang.left(2).toLower();
    if (normalized != m_currentLanguage) {
        m_currentLanguage = normalized;
        loadTranslation();
        
        // Persist
        QSettings settings;
        settings.setValue("language", m_currentLanguage);
        
        emit languageChanged(m_currentLanguage);
    }
}

QStringList I18nManager::availableLanguages() const
{
    return {"ru", "en"};
}

QString I18nManager::languageName(const QString& code)
{
    if (code == "ru") return QStringLiteral("Русский");
    if (code == "en") return QStringLiteral("English");
    return code;
}

void I18nManager::loadTranslation()
{
    // Remove old translation
    qApp->removeTranslator(m_translator.get());
    
    // Try to load translation file
    // Look in: :/translations/ (resource), ./translations/, app dir
    QString fileName = QString("dynam_%1").arg(m_currentLanguage);
    
    bool loaded = false;
    
    // Try resource system first
    loaded = m_translator->load(fileName, ":/translations");
    
    // Try local translations directory
    if (!loaded) {
        loaded = m_translator->load(fileName, QDir::currentPath() + "/translations");
    }
    
    // Try application directory
    if (!loaded) {
        loaded = m_translator->load(fileName, QApplication::applicationDirPath());
    }
    
    if (loaded) {
        qApp->installTranslator(m_translator.get());
    }
}

} // namespace core
