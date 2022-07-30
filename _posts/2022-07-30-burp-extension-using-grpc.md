---
layout: post
title: Writing a Burp Extension which uses grpc under the hood 
tags: [Research Development]
author: mqt @ Ingredous Labs
comment: true
---

## Introduction
Recently I worked on writing a Burp Extension which uses grpc to pass responses to external service that would then further analyze the information. The reason grpc was chosen for this task was due to both its interoperability with other languages and its high throughput. This blog post aims to provide a walkthrough of my experience writing this extension and some pitfalls which were encountered.

## Scaffolding the Burp Extension
To quickly scaffold a Burp Extension, it is highly recommended to use the following [Maven archetype](https://github.com/ise-spolansky/burp-extension-maven-archetype). 
Once the project is setup, you will need to add the following dependencies to your `pom` file:

```
<dependencies>
        <dependency>
            <groupId>javax.annotation</groupId>
            <artifactId>javax.annotation-api</artifactId>
            <version>1.3.2</version>
        </dependency>
        <dependency>
            <groupId>io.grpc</groupId>
            <artifactId>grpc-netty-shaded</artifactId>
            <version>1.45.0</version>
        </dependency>
        <dependency>
            <groupId>io.grpc</groupId>
            <artifactId>grpc-protobuf</artifactId>
            <version>1.45.0</version>
        </dependency>
        <dependency>
            <groupId>io.grpc</groupId>
            <artifactId>grpc-stub</artifactId>
            <version>1.45.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
            <scope>test</scope>
        </dependency>
        <!-- https://mvnrepository.com/artifact/net.portswigger.burp.extender/burp-extender-api -->
        <dependency>
            <groupId>net.portswigger.burp.extender</groupId>
            <artifactId>burp-extender-api</artifactId>
            <version>2.3</version>
        </dependency>
    </dependencies>
```

Furthermore, ensure to add the following plugins as well:
```
<plugins>
            <plugin>
                <groupId>org.xolstice.maven.plugins</groupId>
                <artifactId>protobuf-maven-plugin</artifactId>
                <version>0.6.1</version>
                <configuration>
                    <protocArtifact>com.google.protobuf:protoc:3.21.4:exe:${os.detected.classifier}</protocArtifact>
                    <pluginId>grpc-java</pluginId>
                    <pluginArtifact>io.grpc:protoc-gen-grpc-java:1.48.0:exe:${os.detected.classifier}</pluginArtifact>
                </configuration>
                <executions>
                    <execution>
                        <goals>
                            <goal>compile</goal>
                            <goal>compile-custom</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
            <plugin>
                <artifactId>maven-assembly-plugin</artifactId>
                <configuration>
                    <archive>
                        <manifest>
                            <mainClass></mainClass>
                        </manifest>
                    </archive>
                    <descriptorRefs>
                        <descriptorRef>jar-with-dependencies</descriptorRef>
                    </descriptorRefs>
                </configuration>
            </plugin>
        </plugins>
```

## Boilerplate Code

Provided below is sample code that could be used as a boilerplate to build out the extension.

`BurpExtender.java`
```
//Hello World burp extension taken from https://github.com/PortSwigger/example-hello-world/tree/master/java
package burp;

import proto.ResponseCollectionServiceGrpc;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public static PrintWriter stdout;
    private ResponseCollectionServicerpc.ResponseCollectionServiceBlockingStub stub;

    private Client grpcClient;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Grpc Sample Extension");

        stdout = new PrintWriter(callbacks.getStdout(), true);

        this.grpcClient = Client.getInstance();
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        grpcClient.closeChannel();
    }

    @Override
    public void processHttpMessage(int i, boolean messageIsRequest, IHttpRequestResponse message) {

        if (messageIsRequest) {
            return;
        }

        IRequestInfo reqUrl = helpers.analyzeRequest(message.getHttpService(), message.getRequest());

        grpcClient.sendData(reqUrl.getUrl().toString(), message.getResponse());
    }
}
```

`Client.java`:
```
package burp;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import proto.ResponseCollectionServiceGrpc;
import proto.ResponseCollectionServiceGrpcCollectionServiceOuterClass;

public class Client {

    private static Client instance = null;
    private static ResponseCollectionServiceGrpc.ResponseCollectionServiceStub stub = null;
    private ManagedChannel channel;

    private Client() {
        BurpExtender.stdout.println("instantiating client");
        channel = ManagedChannelBuilder.forTarget("localhost:4040").usePlaintext().build();
        stub = ResponseCollectionServiceGrpc.newStub(channel);

    }

    public static Client getInstance() {
        if (instance == null) {
            instance = new Client();
        }

        return instance;
    }

    private StreamObserver<ResponseCollectionServiceOuterClass.Response> getServerResponseObserver() {
        StreamObserver<ResponseCollectionServiceOuterClass.Response> observer = new StreamObserver<ResponseCollectionServiceOuterClass.Response>() {
            @Override
            public void onNext(ResponseCollectionServiceOuterClass.Response response) {
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onCompleted() {
            }
        };
        return observer;
    }

    public void sendData(String url, byte[] response) {
       ResponseCollectionServiceOuterClass.Request request = ResponseCollectionServiceOuterClass.Request.newBuilder().setUrl(url).setRawresponse(ByteString.copyFrom(response)).build();

        BurpExtender.stdout.printf("DEBUG: sending %s to server\n", url);
        try {
            stub.collectresponse(request, getServerResponseObserver());
        } catch (Exception e) {
        }
    }

    public void closeChannel() {
        channel.shutdownNow();
    }
}
```

`ResponseCollectionService.proto`
```
syntax = 'proto3';

package proto;

service ResponseCollectionService {
	rpc CollectResponse(Request) returns (Response) {}
}

message Request {
	string url = 1;
	bytes rawresponse = 2;
}

// empty response as not sending anything back to Burp
message Response {

}
```

## Pitfalls Encountered

**Note**: At the current time, the latest version of the `grpc` dependencies for Java is `1.48.0`. However I noticed that when using this specific version, the following exception will be thrown when the grpc stub is invoked:

```
Caused by: java.nio.channels.UnsupportedAddressTypeException
at java.base/sun.nio.ch.Net.checkAddress(Net.java:146)
at java.base/sun.nio.ch.Net.checkAddress(Net.java:157)
at java.base/sun.nio.ch.SocketChannelImpl.checkRemote(SocketChannelImpl.java:816)
at java.base/sun.nio.ch.SocketChannelImpl.connect(SocketChannelImpl.java:839)
at io.grpc.netty.shaded.io.netty.util.internal.SocketUtils$3.run(SocketUtils.java:91)
at io.grpc.netty.shaded.io.netty.util.internal.SocketUtils$3.run(SocketUtils.java:88)
at java.base/java.security.AccessController.doPrivileged(AccessController.java:569)
at io.grpc.netty.shaded.io.netty.util.internal.SocketUtils.connect(SocketUtils.java:88)
at io.grpc.netty.shaded.io.netty.channel.socket.nio.NioSocketChannel.doConnect(NioSocketChannel.java:322)
at io.grpc.netty.shaded.io.netty.channel.nio.AbstractNioChannel$AbstractNioUnsafe.connect(AbstractNioChannel.java:248)
at io.grpc.netty.shaded.io.netty.channel.DefaultChannelPipeline$HeadContext.connect(DefaultChannelPipeline.java:1342)
at io.grpc.netty.shaded.io.netty.channel.AbstractChannelHandlerContext.invokeConnect(AbstractChannelHandlerContext.java:548)
at io.grpc.netty.shaded.io.netty.channel.AbstractChannelHandlerContext.connect(AbstractChannelHandlerContext.java:533)
at io.grpc.netty.shaded.io.netty.channel.ChannelDuplexHandler.connect(ChannelDuplexHandler.java:54)
at io.grpc.netty.shaded.io.grpc.netty.WriteBufferingAndExceptionHandler.connect(WriteBufferingAndExceptionHandler.java:157)
at io.grpc.netty.shaded.io.netty.channel.AbstractChannelHandlerContext.invokeConnect(AbstractChannelHandlerContext.java:548)
at io.grpc.netty.shaded.io.netty.channel.AbstractChannelHandlerContext.access$1000(AbstractChannelHandlerContext.java:61)
at io.grpc.netty.shaded.io.netty.channel.AbstractChannelHandlerContext$9.run(AbstractChannelHandlerContext.java:538)
at io.grpc.netty.shaded.io.netty.util.concurrent.AbstractEventExecutor.runTask(AbstractEventExecutor.java:174)
at io.grpc.netty.shaded.io.netty.util.concurrent.AbstractEventExecutor.safeExecute(AbstractEventExecutor.java:167)
at io.grpc.netty.shaded.io.netty.util.concurrent.SingleThreadEventExecutor.runAllTasks(SingleThreadEventExecutor.java:470)
at io.grpc.netty.shaded.io.netty.channel.nio.NioEventLoop.run(NioEventLoop.java:503)
at io.grpc.netty.shaded.io.netty.util.concurrent.SingleThreadEventExecutor$4.run(SingleThreadEventExecutor.java:995)
at io.grpc.netty.shaded.io.netty.util.internal.ThreadExecutorMap$2.run(ThreadExecutorMap.java:74)
at io.grpc.netty.shaded.io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30)
... 1 more
```

When first encountering this exception, I initially thought it was due to maybe the Burp platform version being bundled with a newer version of JDK which in turn packages its own JRE. To test whether this was the issue, I re-created the project locally ensuring it is compiled using the same JDK version that the Burp platform is bundled with, and to my surprise, there was no error. I then tried using the Burp standalone jar with different Java versions and the same error kept occurring. Lastly, as a resort I decided to downgrade the dependency to `1.45.0` and it worked without any issues.
