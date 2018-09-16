<img src="https://images.cooltext.com/5195724.png" align="right">

## easyjax-jetty<br><a href="https://www.easyjax.org/"><img src="https://img.shields.io/badge/EasyJAX--blue.svg"></a>
> Commons Embedded Jetty Wrapper

### Introduction

This project is a light wrapper of the [Jetty Servlet Container][jetty], which provides helpful patterns to developers that desire a lightweight embedded server solution.

### Why **easyjax-jetty**?

#### CohesionFirst

Developed with the CohesionFirst approach, **easyjax-jetty** is built to make a developer's life easier. Made possible by the rigorous conformance to design patterns and best practices in every line of its implementation, **commons-jetty** is simple to use and easy to understand.

#### Cohesive and Simple API for Embedded Servlet Container Initialization

**easyjax-jetty** is created to take full advantage of the `javax.servlet.annotation.*` annotations defined in the [Java Servlet v3 Specification of 2009][servlet-v3-spec]. Designed specifically to avoid non-cohesive config files, **commons-jetty** creates a direct and easy to understand embedded wrapper of the Jetty Servlet Container. **commons-jetty** provides a simple API to initialize a Servlet Container in a JVM, significantly reducing the headache most people have when attempting to accomplish the same with Jetty's raw APIs.

### Significantly Reduces Boilerplate Code

**easyjax-jetty** is intended to reduce the number of lines of code dedicated to the initialization of the server, therefore reducing the space of possible errors, and thus allowing the developer to move to his next task, confidently assured the server will start.

### Getting Started

#### Prerequisites

* [Java 8][jdk8-download] - The minimum required JDK version.
* [Maven][maven] - The dependency management system.

#### Example

1. In your preferred development directory, create a [`maven-archetype-quickstart`][maven-archetype-quickstart] project.

  ```tcsh
  mvn archetype:generate -DgroupId=com.mycompany.app -DartifactId=my-app -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
  ```

2. Add the `mvn.repo.openjax.org` Maven repositories to the POM.

  ```xml
  <repositories>
    <repository>
      <id>mvn.repo.openjax.org</id>
      <url>http://mvn.repo.openjax.org/m2</url>
    </repository>
  </repositories>
  <pluginRepositories>
    <pluginRepository>
      <id>mvn.repo.openjax.org</id>
      <url>http://mvn.repo.openjax.org/m2</url>
    </pluginRepository>
  </pluginRepositories>
  ```
  
3. Next, add the `org.easyjax:easyjax-jetty` dependency to the POM.

  ```xml
  <dependency>
    <groupId>org.easyjax</groupId>
    <artifactId>easyjax-jetty</artifactId>
    <version>1.1.4-SNAPSHOT</version>
  </dependency>
  ```

3. Make `App` extend `org.easyjax.jetty.EmbeddedServletContainer`, and add a constructor.

  ```java
  public class App extends EmbeddedServletContainer {
    public static void main(String[] args) {
    }
    
    public App(int port, String keyStorePath, String keyStorePassword, boolean externalResourcesAccess, Realm realm, Class<? extends HttpServlet> ... servletClasses) {
      super(port, keyStorePath, keyStorePassword, externalResourcesAccess, realm, servletClasses);
    }
  }
  ```

4. Include the server initialization code in `main()`.

  ```java
  public static void main(String[] args) {
    Server server = new Server(8080, null, null, true, null);
    server.start();
    server.join();
  }
  ```

9. Run `App`.

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

<a href="http://cooltext.com" target="_top"><img src="https://cooltext.com/images/ct_pixel.gif" width="80" height="15" alt="Cool Text: Logo and Graphics Generator" border="0" /></a>

[jdk8-download]: http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html
[jetty]: http://www.eclipse.org/jetty/
[maven-archetype-quickstart]: http://maven.apache.org/archetypes/maven-archetype-quickstart/
[maven]: https://maven.apache.org/
[servlet-v3-spec]: http://download.oracle.com/otn-pub/jcp/servlet-3.0-fr-eval-oth-JSpec/servlet-3_0-final-spec.pdf