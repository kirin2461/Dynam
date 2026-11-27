#pragma once

#include <QObject>
#include <QString>

namespace core {

/**
 * @brief Singleton managing application themes.
 * 
 * Supports dark and light themes with runtime switching.
 * Applies Qt stylesheets for consistent theming across all widgets.
 */
class ThemeManager : public QObject {
    Q_OBJECT

public:
    static ThemeManager& instance();
    
    /// Set current theme (dark, light)
    void setTheme(const QString& theme);
    
    /// Get current theme name
    QString currentTheme() const { return m_currentTheme; }
    
    /// Get list of available themes
    QStringList availableThemes() const;
    
    /// Get stylesheet for current theme
    QString currentStylesheet() const;

signals:
    void themeChanged(const QString& theme);

private:
    explicit ThemeManager(QObject* parent = nullptr);
    ~ThemeManager() override;
    
    ThemeManager(const ThemeManager&) = delete;
    ThemeManager& operator=(const ThemeManager&) = delete;
    
    QString getDarkStylesheet() const;
    QString getLightStylesheet() const;

    QString m_currentTheme = "dark";
};

} // namespace core
