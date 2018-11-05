# Libreria
Proyecto base en pathon 
Con una página Web responsiva (HTML – CSS – Media Query).
Utilizando del framework Bootstrap, FontAwesome.
Boton de logueo (login / logout) para poder realizar cambios. (Autenticación local)
Autenticación externa con google
Password Hash.
Utilización de sesiones.
Utilización del ORM SqlAlchemy.
Base de datos SQLITE o POSTGRESQL.
Aplicación ejecutándose en Linux (vagrant).

Los usuarios logueados tienen que tener permisos de Crear, Modificar y Borrar objetos.
Solo los usuarios que hayan creado los objetos podrán editarlos. 
Si no fueron los creadores, no tienen que poder realizar las acciones, solo verlos.
