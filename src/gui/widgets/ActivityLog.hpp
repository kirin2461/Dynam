#pragma once

#include <QWidget>
#include <QStringList>
#include <vector>
#include <string>

class QPlainTextEdit;

// Scrolling log of proxy/core events.
class ActivityLog : public QWidget {
    Q_OBJECT
public:
    explicit ActivityLog(QWidget* parent = nullptr);

    void appendLine(const QString& line);
    // API compat with original skeleton (database activity rows)
    void setLogs(const std::vector<std::string>& logs);

private:
    QPlainTextEdit* edit_;
    int lines_ = 0;
};
