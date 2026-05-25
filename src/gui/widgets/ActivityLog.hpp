#pragma once
#include <QWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include <QVBoxLayout>
#include <QLabel>
#include <QDateTime>
#include <QBrush>
#include <QColor>
#include <QFont>
#include <string>
#include <vector>

class ActivityLog : public QWidget {
    Q_OBJECT
public:
    explicit ActivityLog(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->addWidget(new QLabel("<b>Activity</b>", this));

        list_ = new QListWidget(this);
        list_->setAlternatingRowColors(true);
        QFont mono = list_->font();
        mono.setFamily("Menlo");
        mono.setStyleHint(QFont::Monospace);
        list_->setFont(mono);
        layout->addWidget(list_, 1);
    }

    void setLogs(const std::vector<std::string>& logs) {
        list_->clear();
        const QString ts = QDateTime::currentDateTime().toString("HH:mm:ss");
        for (const auto& line : logs) {
            const QString text = QString::fromStdString(line);
            auto* item = new QListWidgetItem(ts + "  " + text);
            item->setForeground(colorForCategory(text));
            list_->addItem(item);
        }
        if (list_->count() > 0) {
            list_->scrollToBottom();
        }
    }

private:
    // log entries from Database::log_activity look like "[category] message".
    // Pick a hue based on the bracketed prefix; default to neutral.
    static QBrush colorForCategory(const QString& text) {
        if (text.startsWith("[bypass]"))     return QBrush(QColor("#3498db")); // blue
        if (text.startsWith("[connection]")) return QBrush(QColor("#2ecc71")); // green
        if (text.startsWith("[error]"))      return QBrush(QColor("#e74c3c")); // red
        if (text.startsWith("[warning]"))    return QBrush(QColor("#f39c12")); // amber
        return QBrush(QColor("#bdc3c7")); // light grey
    }

    QListWidget* list_;
};
