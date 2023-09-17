# ESC (Embedded Servlet Container)

[![Build Status](https://github.com/openjax/esc/actions/workflows/build.yml/badge.svg)](https://github.com/openjax/esc/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/openjax/esc/badge.svg)](https://coveralls.io/github/openjax/esc)
[![Javadocs](https://www.javadoc.io/badge/org.openjax/esc.svg)](https://www.javadoc.io/doc/org.openjax/esc)
[![Released Version](https://img.shields.io/maven-central/v/org.openjax/esc.svg)](https://mvnrepository.com/artifact/org.openjax/esc)
![Snapshot Version](https://img.shields.io/nexus/s/org.openjax/esc?label=maven-snapshot&server=https%3A%2F%2Foss.sonatype.org)

## Introduction

OpenJAX ESC (Embedded Servlet Container) is a conveneince wrapper of the [Jetty Servlet Container][jetty], which provides helpful patterns to developers that desire a lightweight embedded server solution.

### Simple API for Embedded Servlet Container Initialization

OpenJAX ESC (Embedded Servlet Container) is created to take full advantage of the `javax.servlet.annotation.*` annotations defined in the [Java Servlet v3 Specification of 2009][servlet-v3-spec]. Designed specifically to avoid non-cohesive config files, OpenJAX ESC (Embedded Servlet Container) creates a direct and easy to understand embedded wrapper of the Jetty Servlet Container. OpenJAX ESC (Embedded Servlet Container) provides a simple API to initialize a Servlet Container in a JVM, significantly reducing the headache most people have when attempting to accomplish the same with Jetty's raw APIs.

## Significantly Reduces Boilerplate Code

OpenJAX ESC (Embedded Servlet Container) is intended to reduce the number of lines of code dedicated to the initialization of the server, therefore reducing the space of possible errors, and thus allowing the developer to move to his next task, confidently assured the server will start.

## Getting Started

### Prerequisites

* [Java 8][jdk8-download] - The minimum required JDK version.
* [Maven][maven] - The dependency management system.

### Example

1. Next, add the `org.openjax:embedded-server` dependency to the POM.

   ```xml
   <dependency>
     <groupId>org.openjax.esc</groupId>
     <artifactId>jetty-9</artifactId>
     <version>1.0.0</version>
   </dependency>
   ```

1. Make `App` extend `org.openjax.embeddedserver.EmbeddedJetty9`, and add a constructor.

   ```java
   public class Server extends EmbeddedJetty9 {
     public Server(int port) {
       super(port);
     }
   }
   ```

1. Add the server initialization code in `Server#main()`.

   ```java
   public static void main(String[] args) {
     Server server = new Server(8080);
     server.start();
     server.join();
   }
   ```

1. Run `App`.

## Contributing

Pull requests are welcome. For major changes, please [open an issue](../../issues) first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

[jdk8-download]: http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html
[jetty]: http://www.eclipse.org/jetty/
[maven-archetype-quickstart]: http://maven.apache.org/archetypes/maven-archetype-quickstart/
[maven]: https://maven.apache.org/
[servlet-v3-spec]: http://download.oracle.com/otn-pub/jcp/servlet-3.0-fr-eval-oth-JSpec/servlet-3_0-final-spec.pdf