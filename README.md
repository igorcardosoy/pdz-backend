# 🛠️ PDZ Backend API

  This is the backend API developed for PDZ, built using Spring Boot. It provides core services such as authentication, user authorization, data validation, and integration with a PostgreSQL database. The API **will** communicates with the frontend via RESTful endpoints and handles secure user sessions using JWT and **probably** OAuth2.
  
📦 Key Dependencies

| Dependency                          | Description                             |
| ----------------------------------- | --------------------------------------- |
| `spring-boot-starter-web`           | Builds RESTful web services             |
| `spring-boot-starter-security`      | Secures API endpoints                   |
| `spring-boot-starter-oauth2-client` | Enables OAuth2 login and client support |
| `spring-boot-starter-data-jpa`      | JPA integration for data persistence    |
| `io.jsonwebtoken:jjwt-*`            | JWT creation, parsing, and validation   |
| `org.postgresql:postgresql`         | PostgreSQL JDBC driver                  |
| `org.projectlombok:lombok`          | Reduces boilerplate with annotations    |
