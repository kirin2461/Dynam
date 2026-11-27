#pragma once

#include <QWidget>
#include <QTableView>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>

#include "models/LogModel.hpp"

namespace widgets {

/**
 * @brief Log viewer widget with filtering and search.
 * 
 * Displays log entries in a table with:
 * - Timestamp, level, source, message columns
 * - Level filter (dropdown)
 * - Source filter (dropdown)
 * - Search box (text filter)
 * - Clear logs button
 * - Auto-scroll to latest
 */
class LogWidget : public QWidget {
    Q_OBJECT

public:
    explicit LogWidget(QWidget* parent = nullptr);
    
    /// Add a log entry
    void addEntry(const QJsonObject& entry);
    
    /// Get the log model
    models::LogModel* model() { return m_model; }

signals:
    void clearRequested();

private slots:
    void onLevelFilterChanged(int index);
    void onClearClicked();
    void onSearchTextChanged(const QString& text);

private:
    void setupUi();
    
    models::LogModel* m_model;
    QTableView* m_table;
    
    QComboBox* m_levelFilter;
    QLineEdit* m_searchEdit;
    QPushButton* m_clearButton;
};

} // namespace widgets
