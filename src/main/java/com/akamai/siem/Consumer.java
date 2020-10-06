package com.akamai.siem;

import static java.lang.String.format;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.splunk.modularinput.Event;
import com.splunk.modularinput.EventWriter;

public class Consumer implements Callable<Double> {
  private final BlockingQueue<String> queue;
  private final BlockingQueue<Event> eventQueue;
  private volatile Boolean done;
  private String inputName;
  private EventWriter ew;
  private Integer threadId;
  private ObjectMapper mapper;
  private double runningEdgeGridTime;
  final long startEdgeGrid;

  public Consumer(BlockingQueue<String> queue, BlockingQueue<Event> eventQueue, String inputName, EventWriter ew,
      Integer threadId) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
    this.startEdgeGrid = System.nanoTime();
    this.queue = queue;
    this.done = false;
    this.inputName = inputName;
    this.ew = ew;
    this.threadId = threadId;
    this.eventQueue = eventQueue;
    this.mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);
  }

  public Double call() {

    String firstEvent = null;
    while (done == false) {
      try {
        firstEvent = queue.poll(5, TimeUnit.MILLISECONDS);
        if (firstEvent != null) {
          double startEvent = System.nanoTime();
          if ("poisonPill".equals(firstEvent) == true) {
            // ew.synchronizedLog(EventWriter.INFO,format("poisonPill on thread %d", this.threadId));
            done = true;
          } else {

            Raw raw = mapper.readValue(firstEvent, Raw.class);
            raw.processRaw();

            String payLoad;
            if (raw.getOffset() != null) {
              ew.synchronizedLog(EventWriter.INFO, format("found new offset: %s", raw.getOffset()));
              Main.staticOffset = raw.getOffset();
            }

            payLoad = mapper.writeValueAsString(raw);
            Event event = new Event();
            event.setStanza(inputName);
            event.setData(payLoad);
            this.eventQueue.put(event);
          }
          this.runningEdgeGridTime += System.nanoTime() - startEvent;
        }
      } catch (InterruptedException ie) {
        done = true;
      } catch (Exception ex) {
        Main.logException(ew, ex);
        Main.logException(ew, new Exception(firstEvent));
      }
    }

    return (runningEdgeGridTime);
  }
}
