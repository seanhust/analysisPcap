package model;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class TcpAnalysisListener extends BaseAnalysisPcap implements ActionListener {
    byte[] oneDatagram = new byte[1500];

    @Override
    public void analysis() {
        byte[] data = getNextData();
        if(data == null){
            return;
        }
        byte[] load = new byte[data.length-19];

        int i = 0;
        if (protocol == Protocol.TCP) {
            sourcePort = byteToInt(data[i++]) * 256 + byteToInt(data[i++]);
            destnationPort = byteToInt(data[i++]) * 256 + byteToInt(data[i++]);
            i += 8;
            headerLength = byteToInt(data[i++])/4;
            if(nextLenth - headerLength <= 20){
                return;
            }
            i = i+7;
            fileName.delete(0,fileName.length());
            fileName.append("TCP");
            fileName.append("["+source+"]");
            fileName.append(sourcePort);
            fileName.append("["+destination+"]");
            fileName.append(destnationPort);
            for(int j = 0;i<data.length;i++,j++){
                load[j] = data[i];
            }
            try {
                Path tcpFile = Files.createFile(Paths.get(System.getProperty("user.dir"),"tcpPackage",fileName.toString()));
                RandomAccessFile raf = new RandomAccessFile(tcpFile.toFile(),"rw");
                raf.write(load);
                raf.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            //开始存数据
        } else if (protocol == Protocol.UDP) {

        } else {
            System.out.println("协议解析出错");
        }
    }

    public TcpAnalysisListener(File file, Frame frame, JTextField pcapFilePath) {
        super(file, frame, pcapFilePath);
    }


    @Override
    public void actionPerformed(ActionEvent e) {
        file = new File(pcapFilePath.getText());
        //创建目录
        if (getAllContent()) {

            Path tcpDir = Paths.get(System.getProperty("user.dir"),"tcpPackage");
            try {
                Files.deleteIfExists(tcpDir);
                Files.createDirectory(tcpDir);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            while(currentIndex + 30 < allContent.length){
                analysis();
            }
        }
    }
}
