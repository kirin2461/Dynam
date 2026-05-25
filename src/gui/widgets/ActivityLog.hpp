#pragma once
#include <QWidget>
#include <QListWidget>
#include <QVBoxLayout>
#include <string>
#include <vector>

class ActivityLog : public QWidget {
    Q_OBJECT
public:
    explicit ActivityLog(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        list_ = new QListWidget(this);
        layout->addWidget(list_);
    }
    void setLogs(const std::vector<std::string>& logs) {
        list_->clear();
        for (const auto& line : logs) {
            list_->addItem(QString::fromStdString(line));
        }
    }
private:
    QListWidget* list_;
};
