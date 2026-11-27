#pragma once

#include <QObject>
#include <QTranslator>
#include <QString>
#include <memory>

namespace core {

/**
 * @brief Singleton managing internationalization (i18n) for the application.
 * 
 * Supports Russian (ru) and English (en) languages with runtime switching.
 * Emits languageChanged() signal when language changes, allowing all
 * widgets to update their text.
 */
class I18nManager : public QObject {
    Q_OBJECT

public:
    static I18nManager& instance();
    
    /// Set current language (ru, en)
    void setLanguage(const QString& lang);
    
    /// Get current language code
    QString currentLanguage() const { return m_currentLanguage; }
    
    /// Get list of available languages
    QStringList availableLanguages() const;
    
    /// Get display name for language code
    static QString languageName(const QString& code);

signals:
    void languageChanged(const QString& lang);

private:
    explicit I18nManager(QObject* parent = nullptr);
    ~I18nManager() override;
    
    I18nManager(const I18nManager&) = delete;
    I18nManager& operator=(const I18nManager&) = delete;
    
    void loadTranslation();

    QString m_currentLanguage = "ru";
    std::unique_ptr<QTranslator> m_translator;
};

} // namespace core
