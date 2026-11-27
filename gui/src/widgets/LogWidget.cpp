#include "LogWidget.hpp"

#include <QHeaderView>
#include <QHBoxLayout>
#include <QFont>

namespace widgets {

LogWidget::LogWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void LogWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(16);
    
    // ─── Title ─────────────────────────────────────────────────────────
    auto* titleLabel = new QLabel(tr("Activity Log"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);
    
    // ─── Filters ───────────────────────────────────────────────────────
    auto* filterLayout = new QHBoxLayout();
    filterLayout->setSpacing(12);
    
    // Level filter
    auto* levelLabel = new QLabel(tr("Level:"));
    filterLayout->addWidget(levelLabel);
    
    m_levelFilter = new QComboBox();
    m_levelFilter->addItem(tr("All"), -1);
    m_levelFilter->addItem(tr("Debug"), 0);
    m_levelFilter->addItem(tr("Info"), 1);
    m_levelFilter->addItem(tr("Warning"), 2);
    m_levelFilter->addItem(tr("Error"), 3);
    m_levelFilter->addItem(tr("Critical"), 4);
    m_levelFilter->setCurrentIndex(0);
    connect(m_levelFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LogWidget::onLevelFilterChanged);
    filterLayout->addWidget(m_levelFilter);
    
    // Search
    auto* searchLabel = new QLabel(tr("Search:"));
    filterLayout->addWidget(searchLabel);
    
    m_searchEdit = new QLineEdit();
    m_searchEdit->setPlaceholderText(tr("Filter logs..."));
    connect(m_searchEdit, &QLineEdit::textChanged, this, &LogWidget::onSearchTextChanged);
    filterLayout->addWidget(m_searchEdit);
    
    // Clear button
    m_clearButton = new QPushButton(tr("Clear"));
    connect(m_clearButton, &QPushButton::clicked, this, &LogWidget::onClearClicked);
    filterLayout->addWidget(m_clearButton);
    
    mainLayout->addLayout(filterLayout);
    
    // ─── Table ─────────────────────────────────────────────────────────
    m_model = new models::LogModel(this);
    
    m_table = new QTableView();
    m_table->setModel(m_model);
    m_table->setAlternatingRowColors(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);
    
    // Set column widths
    m_table->setColumnWidth(models::LogModel::ColTimestamp, 200);
    m_table->setColumnWidth(models::LogModel::ColLevel, 80);
    m_table->setColumnWidth(models::LogModel::ColSource, 120);
    
    mainLayout->addWidget(m_table, 1);
}

void LogWidget::addEntry(const QJsonObject& entry)
{
    m_model->addFromJson(entry);
    
    // Auto-scroll to bottom
    if (m_model->rowCount() > 0) {
        m_table->scrollToBottom();
    }
}

void LogWidget::onLevelFilterChanged(int index)
{
    int level = m_levelFilter->itemData(index).toInt();
    m_model->setMinLevel(level >= 0 ? level : 0);
}

void LogWidget::onClearClicked()
{
    m_model->clear();
    emit clearRequested();
}

void LogWidget::onSearchTextChanged(const QString& text)
{
    m_model->setSourceFilter(text);
}

} // namespace widgets
