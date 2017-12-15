package model;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;

/**
 * @author sean
 * BaseAnalysisPcap实现基本的解析Pcap的操作，充当TCP和UDP解析的父类。
 */
abstract public class BaseAnalysisPcap {

    int currentIndex = 24;
    int nextFirstIndex = 0;
    int nextLenth;
    protected File file;
    private byte[] data;
    private int packageLen;
    protected byte[] allContent;
    protected StringBuffer fileName = new StringBuffer(64);
    protected int headerLength;
    protected StringBuffer source = new StringBuffer(16);
    protected StringBuffer destination = new StringBuffer(16);
    protected int sourcePort;
    protected int destnationPort;
    protected byte[] pcapHeader = new byte[24];
    protected Protocol protocol;
    Frame frame;
    JTextField pcapFilePath;
    public BaseAnalysisPcap(File file, Frame frame,JTextField pcapFilePath) {
        this.file = file;
        this.frame = frame;
        this.pcapFilePath = pcapFilePath;
    }

    private void getPcapHeader(){
        for(int i = 0;i<24;i++){
            pcapHeader[i] = allContent[i];
        }
    }

    public abstract void analysis();

    protected boolean getAllContent() {

        if (file == null) {
            JOptionPane.showMessageDialog(frame, "请选择文件");
            return false;
        } else if (!file.getName().matches(".+\\.pcap")) {
            JOptionPane.showMessageDialog(frame, "请选择pcap格式的文件");
            return false;
        } else {
            allContent = new byte[(int) file.length()];
            try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                raf.read(allContent);
                getPcapHeader();
                return true;
            } catch (IOException ex) {
                ex.printStackTrace();
                return true;
            }
        }
    }

    public byte[] getTCPPcap(){
        nextFirstIndex = currentIndex;
        if(allContent.length > currentIndex + 30){
            skipPackageHeader();
            skipEthernetHeader();
            currentIndex += 2;
            getTotalLength();
            getProtocol();
            getSource();
            getDestination();
            data = new byte[packageLen + 16];
            currentIndex = nextFirstIndex;
            for(int i = 0;i<data.length;i++){
                data[i] = allContent[currentIndex++];
            }
            return data;
        }
        return null;
    }

    public byte[] getNextData() {
        nextFirstIndex = currentIndex;
        if(allContent.length > currentIndex + 30){
            skipPackageHeader();
            skipEthernetHeader();
            currentIndex += 2;
            getTotalLength();
            if(nextLenth == 40){
                currentIndex = nextFirstIndex+packageLen+16;
                return null;
            }
            getProtocol();
            getSource();
            getDestination();
            data = new byte[nextLenth];
            for(int i = 0;i<nextLenth-20;i++){
                data[i] = allContent[currentIndex];
                currentIndex ++;
            }
            currentIndex = nextFirstIndex+packageLen+16;
            return data;
        }
        return null;
    }

    private void getSource(){
        source.delete(0,source.length());
        currentIndex += 2;
        for(int i=0;i<4;i++) {
            source.append(byteToInt(allContent[currentIndex]));
            if(i == 3) {
                source.append(':');
            }else{
                source.append('.');
            }
            currentIndex++;
        }

    }

    private void getDestination(){
        destination.delete(0,destination.length());
        for(int i=0;i<4;i++) {
            destination.append(byteToInt(allContent[currentIndex]));
            if(i == 3) {
                destination.append(':');
            }else{
                destination.append('.');
            }
            currentIndex++;
        }
    }

    public void getProtocol() {
        currentIndex += 5;
        if(allContent[currentIndex] == 6){
            currentIndex ++;
            protocol = Protocol.TCP;
        }else if(allContent[currentIndex] == 17){
            currentIndex ++;
            protocol = Protocol.UDP;
        }else{
            return;
        }
    }

    private  void skipPackageHeader(){
        currentIndex += 8;
        int firstLow = byteToInt(allContent[currentIndex++]);
        int firstHigh = byteToInt(allContent[currentIndex++]);
        int secondLow = byteToInt(allContent[currentIndex++]);
        int secondHigh = byteToInt(allContent[currentIndex++]);
        packageLen = firstLow+(firstHigh<<8)+(secondLow<<16)+(secondHigh<<24);
        currentIndex = currentIndex+4;
    }

    private void skipEthernetHeader(){
        currentIndex += 14;
    }


    private void getTotalLength(){
        int high = byteToInt(allContent[currentIndex]);
        currentIndex ++;
        int low = byteToInt(allContent[currentIndex]);
        currentIndex ++;
        nextLenth = high*256+low;
    }

    public  int byteToInt(byte e){
        if(e >= 0){
            return e;
        }else{
            return 256 - (~e + 1);
        }
    }
}

enum Protocol {
    TCP, UDP;
}