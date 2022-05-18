library(jsonlite)
library(curl)
library(tidyjson)
library(dplyr)
library(purrr)
library(tidyverse)
library(jsonlite)
library(rjson)
library(fcaR)
library(parallel)
library(purrr)
library(rlist)
library(devtools)
library(rbenchmark)
library(microbenchmark)
library(kableExtra)
library(factoextra)
library(cluster)
library(fpc)
library(hasseDiagram)
library(arules)
library(tree)
library(ISLR)
library(caTools)
library(caret)
library(rpart)
library(rpart.plot)
setwd("~/clase/proyecto r/Android/")
path <- "~/clase/proyecto r/Android/"
# Creamos una lista con todos los json que hay en el directorio



files <-  list.files(path, pattern = "*.json")
class(files)
cl <- makeCluster(detectCores() -1 )
json_files<-list.files(path =path,pattern="*.json",full.names = TRUE)
## Pruebas en diferencias de tiempo entre paralelizado y usando lapply normal

json_list<-parLapply(cl,json_files,function(x) jsonlite::read_json(path = x, simplifyVector = TRUE))
json_list_2<-parLapply(cl,json_files,function(x) jsonlite::read_json(path = x))
json_list2<-parLapply(cl,json_files,read_json)
system.time(
  test <- lapply(json_files, read_json)
)
system.time(
  test_paralelo <- parLapply(cl,test_rendimiento_parLapply, `[`, c('sha256','scans'))
)
system.time(
  test_normal <- lapply(test_rendimiento_parLapply, `[`, c('sha256','scans'))
)


stopCluster(cl)



json_list_filtrados <- lapply(json_list, `[`, c('sha256',"total", "positives",'scans'))
## Bucle para darle valores 0 1 a los permisos
for (j in 1:length(json_list)) {
  if(length(json_list[[j]][["additional_info"]][["androguard"]][["Permissions"]]) >0){
    for (k in 1:length(json_list[[j]][["additional_info"]][["androguard"]][["Permissions"]])){
      json_list[[j]][["additional_info"]][["androguard"]][["Permissions"]][[k]] <- TRUE
    }
  }
}
json_tabla<- json_list %>%spread_all()
json_tabla$additional_info.androguard.Permissions.android.permission.SYSTEM_ALERT_WINDOW*1
json_tabla$additional_info.androguard.Permissions.android.permission.SYSTEM_ALERT_WINDOW

datos_df_filtrados_sha256_scans <- json_list_filtrados %>%
  spread_all()
tbl$additional_info.androguard.Permissions.android.permission.BLUETOOTH
system.time(
tbl2 <- json_list_2 %>%
  spread_all()
)
tbl3 <- lapply(json_list2 , spread_all)
a<-lapply(tbl3, rbind)
grande<-as.data.frame(tbl2)
data
# https://github.com/colearendt/tidyjson
# https://cran.microsoft.com/snapshot/2017-08-01/web/packages/tidyjson/vignettes/introduction-to-tidyjson.html
# https://rdrr.io/cran/tidyjson/f/vignettes/introduction-to-tidyjson.Rmd
# https://hendrikvanb.gitlab.io/2018/07/nested_data-json_to_tibble/
# https://stackoverflow.com/questions/35421870/reading-multiple-json-files-in-a-directory-into-one-data-frame Pero hemos usado read_json para usar el spread_all
# http://gradientdescending.com/simple-parallel-processing-in-r/
# https://cran.r-project.org/web/packages/jsonlite/jsonlite.pdf
# https://blog.dominodatalab.com/multicore-data-science-r-python
# https://stackoverflow.com/questions/23758858/how-can-i-extract-elements-from-lists-of-lists-in-r
# https://www.alexejgossmann.com/benchmarking_r/
# https://www.rstudio.com/resources/cheatsheets/
# https://cran.r-project.org/web/packages/microbenchmark/microbenchmark.pdf
# https://stats.stackexchange.com/questions/31083/how-to-produce-a-pretty-plot-of-the-results-of-k-means-cluster-analysis
# https://uc-r.github.io/kmeans_clustering
# https://rpubs.com/rdelgado/405322
# https://techvidvan.com/tutorials/decision-tree-in-r/#:~:text=Decision%20trees%20are%20a%20graphical,as%20well%20as%20classification%20problems.
# https://www.guru99.com/r-decision-trees.html
# https://rubenfcasal.github.io/aprendizaje_estadistico/cart-con-el-paquete-rpart.html




json_tabla_no_na <- json_tabla %>% select_if(~!all(is.na(.)))
json_tabla_de_na <- json_tabla %>% select_if(~all(is.na(.)))
object.size(json_tabla_no_na)


#### Segunda parte 
## Procesado de los resultados de los antivirus

## Vamos a usar sha256 como el identificador de cada posible alerta.
sha_datos_scans.detected <- as.data.frame(json_tabla) %>% select( sha256, total, positives , matches("scans.*.detected") )
sha_datos_permisos_positives <- as.data.frame(json_tabla) %>% select( sha256, total, positives , matches("androguard.Permissions.android.permission.*") )
sha_datos_permisos_positives[is.na(sha_datos_permisos_positives)] <- 0

## Los datos numéricos únicamente para evitar dolores de cabeza.
datos_scans.detected <- as.data.frame(tbl) %>% select(  matches("scans.*.detected") )
## Nos sirve para pasar los true y false a 1 o 0.
datos_procesados <- data.frame(datos_scans.detected*1)

tabla_total <- sapply(datos_procesados, table )
tabla_df_total <- data.frame(t(unlist(tabla_total)))

View(t(tabla_df_total))


analisis<-summary(datos_procesados)
analisis_data<- data.frame( analisis)

objects <-sha_datos_scans.detected$sha256
rownames(datos_procesados) <- objects

## Eliminamos las columnas de CYlance y Sentinel One porque son prácticamente todos los valores null y nos rompe la función de na.omit
datos_procesados$scans.Cylance.detected <- NULL
datos_procesados$scans.SentinelOne.detected <- NULL

datos_procesados_no_na <- na.omit(datos_procesados)
nombre_columnas <-names(datos_procesados_no_na)
atributes <- nombre_columnas
## El fcaR funciona pero sólo tenemos 5 valores
fc_detected <- FormalContext$new(datos_procesados_no_na)
print(fc_detected)
fc_detected$plot()




test <- lapply(json_list, `[`, c('sha256', 'total', 'positives','scans'))


est<-list.filter(json_list,scans)
json_list_detected <- lapply(json_list, )

## Prueba de comparción de lectura de ficheros entre parLapply y lapply, para ello he replicado los .json originales hasta obtener 10063 elementos en vez de los 183 originales

path_rendimiento <- "~/clase/proyecto r/Android/Android/Android"
# Creamos una lista con todos los json que hay en el directorio
files_rendimiento <- dir(path_rendimiento, pattern = "*.json")
jsonfiles <- list.files(path = path_rendimiento, pattern=".json", full.names=TRUE)


library(parallel)
cl_rendimiento <- makeCluster(detectCores() -1 )
json_files_rendimiento<-list.files(path = path_rendimiento,pattern="*.json",full.names = TRUE)

## Pruebas en diferencias de tiempo entre paralelizado y usando lapply normal,
tiempo_parLapply <- system.time(test_rendimiento_parLapply<-parLapply(cl_rendimiento,json_files_rendimiento,function(x) jsonlite::read_json(path  = x, simplifyVector =TRUE) ))

tiempo_lapply <- system.time(
  test_rendimiento_lapply <- lapply(jsonfiles, function(x) jsonlite::read_json(path  = x))
)
stopCluster(cl_rendimiento)
## Ratio de mejora de parLapply respecto a lapply:
as.double(tiempo_lapply[3]/tiempo_parLapply[3])


tbl_test <- test_rendimiento_parLapply %>%
  spread_all()
tbl_test
object.size(tbl_test)/2^30
rm(test_rendimiento_parLapply)
tbl_test_grande <- test_rendimiento_lapply %>%
  spread_all()

rm(test_rendimiento_lapply)
test_normal_grande <- lapply( test_rendimiento_parLapply, `[`, c('sha256','scans'))
tbl_test_grande_filtrado <- test_normal_grande %>%
  spread_all()

system.time(
test <- test_rendimiento_parLapply %>% spread_all()
)
system.time(
  test <- test_rendimiento_parLapply[1:10063] %>% spread_all()
)
cl <- makeCluster(detectCores() -1 )
benchmark_lectura_200 <-microbenchmark( parLapply(cl,json_files,function(x) jsonlite::read_json(path = x, simplifyVector = TRUE)), lapply(json_files, function(x) jsonlite::read_json(path = x, simplifyVector = TRUE)), times = 200 )
benchmark_lectura_100 <-microbenchmark( parLapply(cl,json_files,function(x) jsonlite::read_json(path = x, simplifyVector = TRUE)), lapply(json_files, function(x) jsonlite::read_json(path = x, simplifyVector = TRUE)), times = 100 )
stopCluster(cl)
print(benchmark_lectura_100)
autoplot(benchmark_lectura_100)
boxplot(benchmark_lectura)
View(t())
tabla_NAs <- as.data.frame(t(select(tabla_df , matches( "*.NA$"))))
tabla_NAs <- arrange(tabla_NAs, desc(V1) )
nombres_eliminar<- gsub( ".{3}$", "", row.names(tabla_NAs))
###########################################################

json_df_filtrados<-sha_datos_scans.detected
colnames(json_df_filtrados)<-gsub("-" , ".", colnames(json_df_filtrados))
json_df_filtrados<-as.data.frame(json_df_filtrados)
i<-1
total_filas<-0
total<-nrow(sha_datos_scans.detected)
while (total_filas < total*0.9) {
  mayor<- nombres_eliminar[i]
  json_df_filtrados <- select(json_df_filtrados, -mayor)
  total_filas <- nrow (na.omit(json_df_filtrados))
  i<-i+1
}

json_df_filtrados<- na.omit(json_df_filtrados)
datos_df_filtrados <- as.data.frame(select(json_df_filtrados, -c("sha256","total","positives")))
tabla <- sapply(datos_df_filtrados , table)
tabla_df <- data.frame(t(unlist(tabla)))
tabla_unos <- as.data.frame(t(select(tabla_df , matches( "*.TRUE$"))))

objects <- json_df_filtrados$sha256
datos_df_filtrados <- as.data.frame(select(json_df_filtrados, -sha256, -total, -positives))
class(datos_df_filtrados$scans.Bkav.detected[1])
datos_df_filtrados <- datos_df_filtrados*1
json_df_filtrados<- cbind(json_df_filtrados[,1:3], datos_df_filtrados)

## Usamos el análisis con fcaR para buscar posibles reglas entre los antivirus.
fc_detected <- FormalContext$new(datos_df_filtrados)
fc_detected$clarify()
fc_detected$reduce()
plot(fc_detected)
fc_detected$concepts$plot()
concepts
implicaciones <-  fc_detected$find_implications()
implicaciones
c<-fc_detected$concepts[1:2238]
fc_detected$concepts$supremum(c)



## Probamos a ver que conseguimos aplicando kmeans
fviz_nbclust(t(json_df_filtrados[,2:42]), kmeans, nstart= 100  ) 
test_kmeans <- kmeans(t(json_df_filtrados[,2:42]), centers = 5, nstar=100)
fviz_cluster(test_kmeans, data = t(json_df_filtrados[,2:42]) )
## Ahora probamos a realizarle un análisis usando un dendograma y luego lo agruparemos en 5 clústers para comprobar si se corresponden con el resultado de kmeans.
distancias <- dist(t(datos_df_filtrados))
distancias %>% fviz_dist()
clusters <- distancias %>% hclust()
plot(clusters, main="Detectado Antivirus" )
rect.hclust(clusters, k=5 )

                  
    

view(t(json_df_filtrados))



permisos.regresion <- lm(formula = positives  ~ . -total-sha256,  data = sha_datos_permisos_positives )
plot(permisos.regresion)
summary(permisos.regresion)


test_apriori <- apriori(sha_datos_permisos_positives, minlen=2)

fc_permisos <- FormalContext$new(sha_datos_permisos_positives[,4:99])
fc_permisos$clarify()
fc_permisos$reduce()
plot(fc_permisos)
fc_detected$concepts$plot()
concepts
implicaciones <-  fc_detected$find_implications()
implicaciones
c<-fc_detected$concepts[1:2238]
fc_detected$concepts$supremum(c)

sha_datos_permisos_positives.split <- sample.split(sha_datos_permisos_positives, SplitRatio = 0.8 )
sha_datos_permisos_positives.train <- subset(sha_datos_permisos_positives, sha_datos_permisos_positives.split == TRUE)
sha_datos_permisos_positives.test_train <- subset(sha_datos_permisos_positives, sha_datos_permisos_positives.split == FALSE)

permisos.tree <- tree(positives  ~ . -total -sha256,  data = sha_datos_permisos_positives.train )
plot(permisos.tree)
text(permisos.tree , pretty = 0)
permisos.predecir = predict(permisos.tree, sha_datos_permisos_positives.test_train )
permisos.cv <- cv.tree(permisos.tree)
permisos.cv
plot(permisos.cv)

permisos.rpart.class <- rpart(positives  ~ . -total -sha256,  data = sha_datos_permisos_positives.train, method = 'class')
permisos.rpart.anova <- rpart(positives  ~ . -total -sha256,  data = sha_datos_permisos_positives.train, method = 'anova')
rpart.plot(permisos.rpart.class, extra = 100)
rpart.plot(permisos.rpart.anova, extra = 100)

countries <-  json_tabla %>% group_by(submission.submitter_country)
countries <- select(countries, "positives","submission.submitter_country")
## No sirve, cosa que tiene sentido que no haya regresión lineal entre paises y positivos
regresion_region<-lm(formula = positives ~ submission.submitter_country, data=countries )
summary(regresion_region)



countries_paises <- as.data.frame(table(countries))%>% group_by(submission.submitter_country)
countries_positives_circulos<-ggplot(data = countries_paises , aes(y = positives , x = submission.submitter_country , size = Freq , color = submission.submitter_country)) +  geom_point(alpha=0.3) + scale_size(range = c(.1, 18), name="Frecuencia")
ggplotly(countries_positives_circulos)

library(plotly)
install.packages("dashHtmlComponents")
fig <- plot_ly() 
# fig <- fig %>% add_trace( ... )
# fig <- fig %>% layout( ... ) 

library(dash)
library(dashCoreComponents)
library(dashHtmlComponents)

app <- Dash$new()
app$layout(
  htmlDiv(
    list(
      dccGraph(figure=fig) 
    )
  )
)

app$run_server(debug=TRUE, dev_tools_hot_reload=FALSE)
