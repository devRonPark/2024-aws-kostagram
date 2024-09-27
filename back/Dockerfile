# 1. 빌드 이미지(gradle)
FROM gradle:8-jdk17-alpine AS build
# 2. 컨테이너 작업 디렉토리 설정
WORKDIR /app
# 3. Gradle 파일만 복사
COPY build.gradle settings.gradle gradlew ./
COPY gradle ./gradle
# 4. 프로젝트 파일 전체 복사
COPY . .
# 5. gradlew 파일에 실행 권한 추가 부여 (gradlew는 빌드를 진행하기 위한 파일)
# [r: 읽기 권한, w: 쓰기 권한, x: 실행 권한]
RUN chmod +x gradlew
# 6. 빌드 실행
RUN ./gradlew clean build -x test

# 1. openjdk 이미지
FROM openjdk:17-jdk-alpine
# 2. 컨테이너 작업 디렉토리 설정
WORKDIR /app
# 3. 빌드 단계에서 생성된 jar 파일 복사 (build.gradle : jar { enable: false })
COPY --from=build /app/build/libs/*.jar /app/app.jar
# 4. 포트 노출
EXPOSE 8080
# 5. 애플리케이션 실행
ENTRYPOINT [ "java", "-jar", "/app/app.jar" ]

