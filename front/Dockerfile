# 빌드 작업
# 1. Node 이미지 [version.20] 가져오기
FROM node:20 AS build
# 2. 컨테이너에 작업 디렉토리 설정
WORKDIR /app
# 3. package.json & package-lock.json 을 작업 디렉토리에 복사
COPY package*.json ./
# 4. 의존성 업데이트 및 설치
RUN npm update
RUN npm install
# 5. 소스 코드를 컨테이너에 복사
COPY . .
# 6. React 애플리케이션 빌드
RUN npm run build 

# 배포
# 1. Nginx 이미지 가져오기
FROM nginx:alpine 
# 2. Nginx 설정 파일을 교체(덮어 씌우기)
COPY nginx.conf /etc/nginx/conf.d/default.conf
# 3. Nginx 기본 html 파일 삭제
RUN rm -rf /usr/share/nginx/html/*
# 4. 빌드된 React 애플리케이션을 Nginx 디렉토리로 복사
COPY --from=build /app/build /usr/share/nginx/html
# 5. Nginx 포트 노출
EXPOSE 80
# 6. Nginx 서버 실행
CMD ["nginx", "-g", "daemon off;"]