#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QFont>
#include <QBrush>
#include <QColor>
#include <QJsonArray>
#include <QHash>
#include "ScanCommon.hpp"

// Compare two saved bulk scans. Picks ANY two from ScanHistory::list("bulk")
// and renders an asymmetric diff:
//   - URLs in both    → show old grade → new grade, colour-coded by direction
//   - URLs only in A  → "removed" (greyed)
//   - URLs only in B  → "added"   (green-ish)
//
// "Direction" is grade ordinality: A < B < C < D < F. So C→A is an
// improvement (green up arrow); A→C is a regression (red down arrow).
class BulkDiffDialog : public QDialog {
    Q_OBJECT
public:
    explicit BulkDiffDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle(tr("Compare bulk scans"));
        setModal(false);
        resize(1100, 600);

        auto* root = new QVBoxLayout(this);

        // ─── Picker row ─────────────────────────────────────────────
        auto* picker = new QFormLayout;
        leftCombo_  = new QComboBox(this);
        rightCombo_ = new QComboBox(this);
        for (const auto& e : ScanHistory::list("bulk")) {
            leftCombo_->addItem(e.second, e.first);
            rightCombo_->addItem(e.second, e.first);
        }
        if (leftCombo_->count()  >= 2) leftCombo_->setCurrentIndex(1);
        if (rightCombo_->count() >= 1) rightCombo_->setCurrentIndex(0);

        compareBtn_ = new QPushButton(tr("Compare"), this);
        auto* btnRow = new QHBoxLayout;
        btnRow->addStretch(1);
        btnRow->addWidget(compareBtn_);

        picker->addRow(tr("Older snapshot:"), leftCombo_);
        picker->addRow(tr("Newer snapshot:"), rightCombo_);
        root->addLayout(picker);
        root->addLayout(btnRow);

        // ─── Result table ───────────────────────────────────────────
        table_ = new QTableWidget(this);
        table_->setColumnCount(6);
        table_->setHorizontalHeaderLabels({
            tr("URL"), tr("Change"),
            tr("Grade was"), tr("Grade now"),
            tr("Score was"), tr("Score now"),
        });
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setAlternatingRowColors(true);
        table_->setSortingEnabled(true);
        table_->horizontalHeader()->setStretchLastSection(false);
        table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table_->verticalHeader()->setVisible(false);
        root->addWidget(table_, 1);

        summary_ = new QLabel(this);
        summary_->setStyleSheet("color:#888; padding:4px;");
        root->addWidget(summary_);

        connect(compareBtn_, &QPushButton::clicked, this, &BulkDiffDialog::doCompare);

        if (leftCombo_->count() >= 2) doCompare();   // auto-run if possible
        else summary_->setText(tr("Need at least two saved bulk runs to compare."));
    }

private slots:
    void doCompare() {
        if (leftCombo_->count() == 0 || rightCombo_->count() == 0) return;
        const auto leftDoc  = ScanHistory::load(leftCombo_->currentData().toString());
        const auto rightDoc = ScanHistory::load(rightCombo_->currentData().toString());
        if (!leftDoc.isArray() || !rightDoc.isArray()) return;

        QHash<QString, QJsonObject> leftByUrl, rightByUrl;
        for (const auto& v : leftDoc.array())  {
            const auto o = v.toObject();
            leftByUrl.insert(o.value("request_url").toString(), o);
        }
        for (const auto& v : rightDoc.array()) {
            const auto o = v.toObject();
            rightByUrl.insert(o.value("request_url").toString(), o);
        }

        // Union of URLs from both sides
        QSet<QString> urls;
        for (const auto& k : leftByUrl.keys())  urls.insert(k);
        for (const auto& k : rightByUrl.keys()) urls.insert(k);

        table_->setSortingEnabled(false);
        table_->setRowCount(0);

        int added = 0, removed = 0, improved = 0, regressed = 0, unchanged = 0;

        for (const QString& url : urls) {
            const bool inL = leftByUrl.contains(url);
            const bool inR = rightByUrl.contains(url);
            QString gradeL, gradeR;
            int scoreL = 0, scoreR = 0, maxL = 0, maxR = 0;
            if (inL) {
                const auto sec = leftByUrl[url].value("security").toObject();
                gradeL = sec.value("grade").toString();
                scoreL = sec.value("score").toInt();
                maxL   = sec.value("max").toInt();
            }
            if (inR) {
                const auto sec = rightByUrl[url].value("security").toObject();
                gradeR = sec.value("grade").toString();
                scoreR = sec.value("score").toInt();
                maxR   = sec.value("max").toInt();
            }

            QString change;
            QColor  rowColor = Qt::transparent;
            if (!inL) {                          ++added;     change = "+ added";     rowColor = QColor("#2ecc7133"); }
            else if (!inR) {                     ++removed;   change = "− removed";  rowColor = QColor("#7f8c8d33"); }
            else if (gradeR == gradeL && scoreR == scoreL) { ++unchanged; change = "= unchanged"; }
            else {
                const int dir = gradeRank(gradeL) - gradeRank(gradeR);  // positive = better
                if (dir > 0)      { ++improved;  change = QString("▲ %1 → %2").arg(gradeL, gradeR); rowColor = QColor("#2ecc7133"); }
                else if (dir < 0) { ++regressed; change = QString("▼ %1 → %2").arg(gradeL, gradeR); rowColor = QColor("#e74c3c33"); }
                else              { ++unchanged; change = QString("≈ %1 score change").arg(scoreR - scoreL); }
            }

            const int row = table_->rowCount();
            table_->insertRow(row);
            auto setCol = [&](int col, const QString& text){
                auto* it = new QTableWidgetItem(text);
                it->setFlags(it->flags() & ~Qt::ItemIsEditable);
                if (rowColor != Qt::transparent) it->setBackground(rowColor);
                table_->setItem(row, col, it);
            };
            setCol(0, url);
            setCol(1, change);
            setCol(2, inL ? gradeL : "—");
            setCol(3, inR ? gradeR : "—");
            setCol(4, inL ? QString::number(scoreL) : "—");
            setCol(5, inR ? QString::number(scoreR) : "—");
        }
        table_->setSortingEnabled(true);
        for (int c = 1; c < 6; ++c) table_->resizeColumnToContents(c);
        summary_->setText(
            tr("▲ %1 improved · ▼ %2 regressed · + %3 added · − %4 removed · = %5 unchanged")
                .arg(improved).arg(regressed).arg(added).arg(removed).arg(unchanged));
    }

private:
    // A=4 (best) → F=0 (worst). Anything unknown sits at -1 so it sorts
    // below F (rather than being treated as "best by absence of bad data").
    static int gradeRank(const QString& g) {
        if (g == "A") return 4;
        if (g == "B") return 3;
        if (g == "C") return 2;
        if (g == "D") return 1;
        if (g == "F") return 0;
        return -1;
    }

    QComboBox*    leftCombo_;
    QComboBox*    rightCombo_;
    QPushButton*  compareBtn_;
    QTableWidget* table_;
    QLabel*       summary_;
};
