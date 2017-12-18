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

    Path tcpLoad;

    @Override
    public void analysis() {
        byte[] data = getNextData();
        if(data == null){
            return;
        }
        byte[] load = new byte[data.length-19];
        int i = 0;
        if (protocol == Protocol.TCP) {
            sourcePort = byteToInt(data[i++]) * 256;
            sourcePort += byteToInt(data[i++]);
            destnationPort = byteToInt(data[i++]) * 256;
            destnationPort+= byteToInt(data[i++]);
            i += 8;
            headerLength = byteToInt(data[i++])/4;
            if(nextLenth - headerLength <= 20){
                return;
            }
            i = i+7;
            fileName.delete(0,fileName.length());
            fileName.append("TCP");
            fileName.append("["+source+sourcePort+"]");
            fileName.append("["+destination+destnationPort+"]");
            fileName.append(".txt");
            for(int j = 0;i<data.length;i++,j++){
                load[j] = data[i];
            }
            try {
                Path tcpFile = Paths.get(tcpLoad.toFile().toString(),fileName.toString());
                if(!Files.exists(tcpFile)){
                    Files.createFile(tcpFile);
                }
                RandomAccessFile raf = new RandomAccessFile(tcpFile.toFile(),"rw");
                raf.write(load);
                raf.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
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
        Path temp = Paths.get(file.getParent());
        tcpLoad = Paths.get(temp.toFile().getParent(),file.getName().substring(0,file.getName().length()-5));
        if(!Files.exists(tcpLoad)){
            try {
                Files.createDirectory(tcpLoad);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
        //创建目录
        if (getAllContent()) {
            while(currentIndex + 30 < allContent.length){
                analysis();
            }
            JOptionPane.showMessageDialog(frame,"负载已提取完成");
        }
    }
}
