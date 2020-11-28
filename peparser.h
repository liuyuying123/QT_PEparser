#ifndef PEPARSER_H
#define PEPARSER_H
#include<windows.h>
#include<QWidget>
#include<winnt.h>
#include <QMainWindow>
#include "ui_mainwindow.h"
class PEparser:public QMainWindow
{
    Q_OBJECT

private:
    //声明相关的结构体
    char* file_name;
    FILE* fp=NULL;
    void* f_file_buffer;//文件buffer
    PIMAGE_DOS_HEADER p_dos_header;
    PIMAGE_NT_HEADERS p_nt_header;
    PIMAGE_FILE_HEADER p_file_header;
    PIMAGE_OPTIONAL_HEADER p_optional_header;
    PIMAGE_SECTION_HEADER p_section_header;

public:
    explicit PEparser(QWidget* parent=nullptr);
    ~PEparser();
    char* init_file_buffer(char* filename);
    void initdosheader();
    void initntheader();
    void initsectionheader();




    void show_dosheader();
    void show_ntheader();
    void show_fileheader();
    void show_optionalheader();
    void show_sectionheaders();

    void show_sectioninfo();
    void show_datadirectory();
    void show_importtable();
    void show_exporttable();
    void show_relocationtable();
    DWORD rva2foa(DWORD rva);
    int length(FILE* fp);


public slots:
    void slot_init(Ui::MainWindow*);
    void slot_dos_nt(Ui::MainWindow*);
    void slot_section(Ui::MainWindow*);
    void slot_export(Ui::MainWindow*);





};

#endif // PEPARSER_H
