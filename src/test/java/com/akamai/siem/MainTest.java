package com.akamai.siem;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Test;

import com.akamai.edgegrid.signer.ClientCredential;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridInterceptor;
import com.akamai.edgegrid.signer.apachehttpclient.ApacheHttpClientEdgeGridRoutePlanner;
import com.splunk.modularinput.Event;
import com.splunk.modularinput.EventWriter;

public class MainTest {
  static long numRecords = 0l;

  @Test
  public void testkv() throws Exception {



    /*
     * Config config = new Config.Builder().omitDefaultValue(true).build();
     * 
     * Raw raw = JsonIterator.deserialize(config, testInput, Raw.class); raw.processRaw();
     * 
     * 
     * String outStr = JsonStream.serialize(config, raw.getAttackData());
     * 
     * System.out.println(outStr);
     */



  }

  @Test
  public void testLiveFeed() throws Exception {

    long localStart = System.nanoTime();
    final int cores = Runtime.getRuntime().availableProcessors();
    final int coreCnt = cores > 1 ? (cores - 1) : cores;

    EventWriter ew = new EventWriter();

    BlockingQueue<String> queue = new LinkedBlockingQueue<String>(1024 * 256);
    BlockingQueue<Event> eventQueue = new LinkedBlockingQueue<Event>(1024 * 512);
    ExecutorService consumerExecutorService = Executors.newFixedThreadPool(coreCnt - 1);
    for (int i = 0; i < coreCnt; i++) {
      consumerExecutorService.submit(new Consumer(queue, eventQueue, "inputName", ew, i));
    }

    ExecutorService eventExecutorService = Executors.newFixedThreadPool(1);
    eventExecutorService.submit(new EventConsumer(eventQueue, ew));

    String initial_epoch_time = "1600954599";
    String final_epoch_time = "";
    String offset = "";
    String limit = "100";
    String hostname = "akab-cpk7hrm4kmze2xa4-yyj6ikjyr2g7xoxl.cloudsecurity.akamaiapis.net";
    String configIds = "9852;51755";
    String clearAccessToken = "akab-cphlozb5v2dnbrg2-d5jpv44l5yxqjslh";
    String clearClientToken = "akab-4mexpnea3ca7j5k5-yupbuv35abm6rcq2";
    String clearClientSecret = "91PweJzHAnUltxDlKi+eQj67E5CycvpSYG7vQHg1g58=";

    String queryString = Main.processQueryString(initial_epoch_time, final_epoch_time, offset, limit);
    String urlToRequest = "https://" + hostname + "/siem/v1/configs/" + configIds + queryString;
    System.out.println(urlToRequest);
    final long startEdgeGrid = System.nanoTime();
    ClientCredential credential = ClientCredential.builder().accessToken(clearAccessToken).clientToken(clearClientToken)
        .clientSecret(clearClientSecret).host(hostname).build();
    HttpClient client =
        HttpClientBuilder.create().addInterceptorFirst(new ApacheHttpClientEdgeGridInterceptor(credential))
            .setRoutePlanner(new ApacheHttpClientEdgeGridRoutePlanner(credential)).build();
    HttpGet request = new HttpGet(urlToRequest);

    try {
      HttpResponse response = client.execute(request);

      int statusCode = response.getStatusLine().getStatusCode();


      if (statusCode == HttpStatus.SC_OK) {
        InputStream instream = response.getEntity().getContent();

        final double endEdgeGrid = System.nanoTime() - startEdgeGrid;
        final double totalThusFar = System.nanoTime() - localStart;

        System.out.println(String.format("     EdgeGrid time: %.2f s\n", endEdgeGrid / SECONDS.toNanos(1)));
        System.out.println(String.format("        Total time: %.2f s\n", totalThusFar / SECONDS.toNanos(1)));

        // ArrayList<String> testArray = new ArrayList<String>();
        try (BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(instream))) {
          String line;
          while ((line = bufferedreader.readLine()) != null) {
            numRecords++;
            // testArray.add(line);
            queue.put(line);
          }

          for (int i = 0; i < coreCnt; i++) {
            queue.put("poisonPill");
          }

          System.out.println("notifying threads of shutdown....");
          consumerExecutorService.shutdown();
          consumerExecutorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
          final double realTime = System.nanoTime() - localStart;

          System.out.println("             Cores: " + cores);
          // System.out.format(" CPU time: %.2f s\n", cpuTime / SECONDS.toNanos(1));
          System.out.format("         Real time: %.2f s\n", realTime / SECONDS.toNanos(1));
          // System.out.format(" CPU utilization: %.2f%%\n", 100.0 * cpuTime / realTime / cores);
          System.out.format("   Lines Processed: %d\n\n", numRecords);

        } catch (IOException ioe) {
          throw ioe;
        }
      }
    } catch (Exception ex) {
      System.out.println(ex.toString());
    }

  }

  @Test
  public void testProducerConsumer() throws Exception {

    final long start = System.nanoTime();
    EventWriter ew = new EventWriter();
    String testFile = "com/akamai/siem/single_test_dlr.json";
    BlockingQueue<String> queue = new LinkedBlockingQueue<String>(1024 * 256);
    BlockingQueue<Event> eventQueue = new LinkedBlockingQueue<Event>(1024 * 512);
    // Integer coreCnt = Runtime.getRuntime().availableProcessors() * 2;
    Integer coreCnt = 1;

    ExecutorService consumerExecutorService = Executors.newFixedThreadPool(coreCnt);
    for (int i = 0; i < coreCnt; i++) {
      consumerExecutorService.submit(new Consumer(queue, eventQueue, "inputName", ew, i));
    }

    InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(testFile);
    try (BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(inputStream))) {
      String line;

      while ((line = bufferedreader.readLine()) != null) {
        numRecords++;
        queue.put(line);
      }

      for (int i = 0; i < (coreCnt); i++) {
        queue.put("poisonPill");
      }

      System.out.println(String.format("%d", queue.size()));
      consumerExecutorService.shutdown();
      try {
        consumerExecutorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
      } catch (InterruptedException e) {

      }
      System.out.println(String.format("%d", queue.size()));
      final double realTime = System.nanoTime() - start;
      System.out.format("         Real time: %.2f s\n", realTime / SECONDS.toNanos(1));
    } catch (IOException ioe) {
      System.out.println(ioe.toString());
    } catch (InterruptedException ie) {
      System.out.println(ie.toString());
    }

  }
}
