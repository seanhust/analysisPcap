package model;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class TCPPcapList extends BaseAnalysisPcap implements ActionListener {

    public TCPPcapList(File file, Frame frame, JTextField pcapFilePath) {
        super(file, frame, pcapFilePath);
    }
    //用于将多个pcap命一个名字
    String showFileName;
    @Override
    public void analysis() {
        //通过使用文件名区分不同的pcap
        file = new File(pcapFilePath.getText());
        Path tcpList = Paths.get(file.getParent(),file.getName().substring(0,file.getName().length()-5)+"tcpList.txt");
        Path tcpPackage = Paths.get(file.getParent(),file.getName().substring(0,file.getName().length()-5)+"tcpPackage");
        if(!Files.exists(tcpPackage)){
            try {
                Files.createDirectory(tcpPackage);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if(!Files.exists(tcpList)){
            try {
                Files.createFile(tcpList);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        String lastFilename = null;
        while (currentIndex + 30 < allContent.length) {
            final int addIndex = 50;
            byte[] data = getTCPPcap();
            if (data == null) {
                return;
            }
            int i = addIndex;
            if (protocol == Protocol.TCP) {
                sourcePort = byteToInt(data[i++]) * 256;
                sourcePort += byteToInt(data[i++]);
                destnationPort = byteToInt(data[i++]) * 256;
                destnationPort += byteToInt(data[i++]);
                fileName.delete(0, fileName.length());
                fileName.append("TCP");
                fileName.append("[" + source + sourcePort + "]");
                fileName.append("[" + destination + destnationPort + "]");
                fileName.append(".pcap");

                //出现异常未关闭raf。
                if (lastFilename == null || !compare(fileName.toString(),lastFilename)) {
                    //标志是否有新建了文件
                    boolean tag = false;
                    try {
                        Path oneTCPPcap = Paths.get(tcpPackage.toString(), fileName.toString());
                        if(!Files.exists(oneTCPPcap)){
                            Files.createFile(oneTCPPcap);
                            showFileName = oneTCPPcap.toString();
                            tag = true;
                        }
                        RandomAccessFile raf = new RandomAccessFile(oneTCPPcap.toFile(), "rw");
                        raf.write(pcapHeader);
                        raf.write(data);
                        lastFilename = fileName.toString();
                        raf.close();
                        if(tag) {
                            RandomAccessFile tcpListRaf = new RandomAccessFile(tcpList.toFile(), "rw");
                            tcpListRaf.seek(tcpListRaf.length());
                            tcpListRaf.writeBytes(fileName.toString());
                            tcpListRaf.writeBytes("\r\n");
                            tcpListRaf.close();
                        }
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                } else {
                    try {
                        RandomAccessFile raf = new RandomAccessFile(showFileName,"rw");
                        raf.seek(raf.length());
                        raf.write(data);
                        lastFilename = fileName.toString();
                        raf.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    //第二个参数为上次的文件名
    private boolean compare(String first,String second){
        if(first.equals(second)){
            return true;
        }
        StringBuffer temp = new StringBuffer(64);
        temp.append("TCP");
        temp.append("[" + destination + destnationPort + "]");
        temp.append("[" + source + sourcePort + "]");
        temp.append(".pcap");
        if(temp.toString().equals(second))
        {
            return true;
        }
        return false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        file = new File(pcapFilePath.getText());
        //创建目录
        if (getAllContent()) {
            analysis();
        }
        JOptionPane.showMessageDialog(frame,"Pcap文件已提取在原文件目录下");
    }
}
