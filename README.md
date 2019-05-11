# OpenJAX Jetty

> A Convenient Embedded Jetty Pattern

[![Build Status](https://travis-ci.org/openjax/jetty.png)](https://travis-ci.org/openjax/jetty)
[![Coverage Status](https://coveralls.io/repos/github/openjax/jetty/badge.svg)](https://coveralls.io/github/openjax/jetty)
[![Javadocs](https://www.javadoc.io/badge/org.openjax/jetty.svg)](https://www.javadoc.io/doc/org.openjax/jetty)
[![Released Version](https://img.shields.io/maven-central/v/org.openjax/jetty.svg)](https://mvnrepository.com/artifact/org.openjax/jetty)

## Introduction

OpenJAX Jetty is a conveneince wrapper of the [Jetty Servlet Container][jetty], which provides helpful patterns to developers that desire a lightweight embedded server solution.

### Simple API for Embedded Servlet Container Initialization

OpenJAX Jetty is created to take full advantage of the `javax.servlet.annotation.*` annotations defined in the [Java Servlet v3 Specification of 2009][servlet-v3-spec]. Designed specifically to avoid non-cohesive config files, OpenJAX Jetty creates a direct and easy to understand embedded wrapper of the Jetty Servlet Container. OpenJAX Jetty provides a simple API to initialize a Servlet Container in a JVM, significantly reducing the headache most people have when attempting to accomplish the same with Jetty's raw APIs.

## Significantly Reduces Boilerplate Code

OpenJAX Jetty is intended to reduce the number of lines of code dedicated to the initialization of the server, therefore reducing the space of possible errors, and thus allowing the developer to move to his next task, confidently assured the server will start.

## Getting Started

### Prerequisites

* [Java 8][jdk8-download] - The minimum required JDK version.
* [Maven][maven] - The dependency management system.

### Example

1. In your preferred development directory, create a [`maven-archetype-quickstart`][maven-archetype-quickstart] project.

  ```bash
  mvn archetype:generate -DgroupId=com.mycompany.app -DartifactId=my-app -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
  ```

1. Next, add the `org.openjax:jetty` dependency to the POM.

  ```xml
  <dependency>
    <groupId>org.openjax</groupId>
    <artifactId>jetty</artifactId>
    <version>1.1.4-SNAPSHOT</version>
  </dependency>
  ```

1. Make `App` extend `org.openjax.jetty.EmbeddedServletContainer`, and add a constructor.

  ```java
  public class Server extends EmbeddedServletContainer {
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

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

[jdk8-download]: http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html
[jetty]: http://www.eclipse.org/jetty/
[maven-archetype-quickstart]: http://maven.apache.org/archetypes/maven-archetype-quickstart/
[maven]: https://maven.apache.org/
[servlet-v3-spec]: http://download.oracle.com/otn-pub/jcp/servlet-3.0-fr-eval-oth-JSpec/servlet-3_0-final-spec.pdf