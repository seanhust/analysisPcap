package view;

import model.TcpAnalysisListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class View {
    private JFrame frame;
    private JPanel firstPage;
    private JButton pickUpSession;
    private JButton pickUpLoad;
    private JLabel pcapFileLable;
    private JTextField pcapFilePath;
    private JButton pcapFileSelect;
    private JButton pickUpTcp,pickUpUdp;
    private JButton tcpLoad,udpLoad,tcpSession;
    File file = null;

    public View(){
        frame = new JFrame("SessionPickUp");
        frame.setSize(1000,700);
        firstPage = new JPanel(null);

        pickUpSession = new JButton("提取TCP和UDP页面");
        pickUpLoad = new JButton("提取负载页面");
        pickUpSession.setBounds(5,5,160,30);
        pickUpLoad.setBounds(190,5,160,30);
        pcapFileLable = new JLabel("请选择pcap文件:");
        pcapFileLable.setBounds(100,100,160,30);
        pcapFilePath = new JTextField();
        pcapFilePath.setBounds(260,100,500,30);
        pcapFileSelect = new JButton("选择文件");
        pcapFileSelect.setBounds(840,100,100,30);

        pickUpTcp = new JButton("提取TCP");
        pickUpUdp = new JButton("提取UDP");
        pickUpTcp.setBounds(350,400,150,30);
        pickUpUdp.setBounds(550,400,150,30);
        tcpLoad = new JButton("提取TCP负载");
        udpLoad = new JButton("提取UDP负载");
        tcpSession = new JButton("提取TCP会话");
        tcpLoad.setBounds(250,400,150,30);
        udpLoad.setBounds(450,400,150,30);
        tcpSession.setBounds(650,400,150,30);
        firstPage.add(pickUpTcp);
        firstPage.add(pickUpUdp);
        firstPage.add(pickUpLoad);
        firstPage.add(pickUpSession);
        firstPage.add(pcapFileLable);
        firstPage.add(pcapFilePath);
        firstPage.add(pcapFileSelect);
        frame.add(firstPage);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
    }

    public void displayIndex(){
        pickUpLoad.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!firstPage.isAncestorOf(tcpLoad)){
                    System.out.println(firstPage.getComponents());
                    firstPage.remove(pickUpTcp);
                    firstPage.remove(pickUpUdp);
                    firstPage.add(tcpLoad);
                    firstPage.add(tcpSession);
                    firstPage.add(udpLoad);
                    //更新panel否则不会显示
                    firstPage.updateUI();
                    firstPage.repaint();
                    System.out.println(firstPage.getComponents());
                }
            }
        });

        pickUpSession.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!firstPage.isAncestorOf(pickUpTcp)){
                    firstPage.remove(tcpLoad);
                    firstPage.remove(tcpSession);
                    firstPage.remove(udpLoad);
                    firstPage.add(pickUpTcp);
                    firstPage.add(pickUpUdp);
                    firstPage.updateUI();
                    firstPage.repaint();
                }
            }
        });
    }

    public void addActionListener(){
        pcapFileSelect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int val = fileChooser.showOpenDialog(frame);
                if(val == JFileChooser.APPROVE_OPTION){
                    file = fileChooser.getSelectedFile();
                    pcapFilePath.setText(file.getPath());
                }
            }
        });
        TcpAnalysisListener tcpListener = new TcpAnalysisListener(file,frame,pcapFilePath);
        pickUpTcp.addActionListener(tcpListener);
    }

    public static void main(String[] args){
        View view = new View();
        view.displayIndex();
        view.addActionListener();
    }
}



