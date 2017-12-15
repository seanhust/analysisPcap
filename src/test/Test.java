package test;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Test {
    public static void main(String[] args){
        File file  = new File("/home/sean/IdeaProjects/TwoLazy/resource/样例.pcap");
        byte[] content = allContent(file);
    }

    public static byte[] allContent(File file){
        try (RandomAccessFile raf = new RandomAccessFile(file,"r")){
//            File path = new File(System.getProperty("user.dir"));

            StringBuffer a = new StringBuffer(50);
            a.append("fasdfasd"+"d");
            System.out.println(a.toString());
        }catch (IOException e){
            e.printStackTrace();
        }
        return null;
    }

    public static int byteToInt(byte e){
        if(e > 0){
            return e;
        }else{
            return 256 - (~e + 1);
        }
    }
}
