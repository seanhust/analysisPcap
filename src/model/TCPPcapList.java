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

    @Override
    public void analysis() {
        file = new File(pcapFilePath.getText());
        Path tcpList = Paths.get(file.getParent(),"tcpList.txt");
        Path tcpPackage = Paths.get(file.getParent(),"tcpPackage");
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
        while (currentIndex + 30 < allContent.length) {
            String lastFilename = null;
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
                if (lastFilename == null || !fileName.equals(lastFilename)) {
                    try {
                        Path oneTCPPcap = Paths.get(tcpPackage.toString(), fileName.toString());
                        if(!Files.exists(oneTCPPcap)){
                            Files.createFile(oneTCPPcap);
                        }
//                        Path oneTCPPcap = Files.createFile(tcpPcap);
                        RandomAccessFile raf = new RandomAccessFile(oneTCPPcap.toFile(), "rw");
                        raf.write(pcapHeader);
                        raf.write(data);
                        lastFilename = fileName.toString();
                        raf.close();
                        RandomAccessFile tcpListRaf = new RandomAccessFile(tcpList.toFile(),"rw");
                        tcpListRaf.seek(tcpListRaf.length());
                        tcpListRaf.writeBytes(fileName.toString());
                        tcpListRaf.writeBytes("\r\n");
                        tcpListRaf.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                } else if (fileName.equals(lastFilename)) {
                    try {
                        RandomAccessFile raf = new RandomAccessFile(file.getParent() + fileName.toString(), "rw");
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

    @Override
    public void actionPerformed(ActionEvent e) {
        file = new File(pcapFilePath.getText());
        //创建目录
        if (getAllContent()) {
//            Path tcpLoadDir = Paths.get(file.getParent(), "tcpLoad");
//            Path tcpLoadFile = Paths.get(file.getPath(), "tcpLoad", file.getName());
//            if (!Files.exists(tcpLoadDir)) {
//                try {
//                    Files.createDirectory(tcpLoadDir);
//                } catch (IOException ex) {
//                    ex.printStackTrace();
//                }
//            }
//            try {
//                Files.deleteIfExists(tcpLoadFile);
//                Files.createFile(tcpLoadFile);
//            } catch (IOException e1) {
//                e1.printStackTrace();
//            }
            analysis();
        }
        JOptionPane.showMessageDialog(frame,"Pcap文件已提取在原文件目录下");
    }
}
