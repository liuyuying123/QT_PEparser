#include "mainwindow.h"
#include "peparser.h"
#include<QTWidgets>
#include <QPushButton>
#include <QFileDialog>
#include <QTextStream>
#include "ui_mainwindow.h"
#include <windows.h>
#include "QDebug"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //在MainWindow的构造函数中新建一个PE对象？试试看
    this->pe=new PEparser();
    connect(this,&MainWindow::import1,pe,&PEparser::slot_init);//信号连接
    connect(this,&MainWindow::import2,pe,&PEparser::slot_dos_nt);//信号连接
    connect(this,&MainWindow::import3,pe,&PEparser::slot_section);//信号连接
    connect(this,&MainWindow::import4,pe,&PEparser::slot_export);//信号连接


}


void MainWindow::open(){
    if(this->opened==-1){//表明没有文件打开
        QString filename=QFileDialog::getOpenFileName(this);
        if(!filename.isEmpty()){
            //将filename保存在MainWindow的私有属性中，这样在调用PE对象的时候就可以
            //在函数中使用了
            char* filename_a;
            QByteArray ba=filename.toLatin1();
            filename_a=ba.data();//转换为了ascii编码
            this->filename=filename_a;
            this->loadFile(filename_a);
            ui->file_name_label->setText((filename));
            char* show_info="";
            show_info=this->pe->init_file_buffer(this->filename);//初始化所有的PE数据
            ui->information_text->clear();
            ui->information_text->append(show_info);
        }
        else{
           ui->information_text->clear();
           ui->information_text->append("open file failed!");
        }

    }

}



bool MainWindow::loadFile(const QString &filename){

}






MainWindow::~MainWindow()
{
    delete ui;
    delete this->pe;
}


void MainWindow::on_action_close_triggered()
{

}

void MainWindow::on_action_open_triggered()
{
    open();
}

void MainWindow::on_pushButton_init_clicked()
{
    emit import1(ui);//发送信号，将Ui传递到PEparser
}

void MainWindow::on_pushButton_dos_nt_header_clicked()
{
    emit import2(ui);//依旧是发送信号
}

void MainWindow::on_pushButton_sectioninfo_clicked()
{
    emit import3(ui);//发送信号
}

void MainWindow::on_pushButton_export_clicked()
{
    emit import4(ui);//发送信号
}
