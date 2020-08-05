import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime,Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class Autor(Base):
	__tablename__ = 'Autor'

	IdAutor = Column(Integer, primary_key=True)
	Nobreyapellido = Column(String(50), nullable=False)
	Biografia = Column(String(250), nullable=False)
	Fecha_nacimiento = Column(DateTime, nullable=False)
	UserID = Column(String(250),nullable=False)
	
class Libros(Base):	
	__tablename__ = 'Libros'
	
	IdLibro = Column(Integer, primary_key=True)
	NombreLibro = Column(String(50), nullable=False)
	Epigrafe = Column(String(250), nullable=False)
	Fecha_creacion = Column(DateTime, nullable=False)
	UserID = Column(String(250), nullable=False)

class Edicion(Base):	
	__tablename__ = 'Edicion'

	IdEdicion = Column(Integer, primary_key=True)
	IdLibro = Column(Integer, nullable=False)
	IdAutor = Column(Integer,  nullable=False)
	Fecha_Edicion = Column(DateTime, nullable=False)
	Cantidad = Column(Integer, nullable=False)
	Precio = Column(Float(2), nullable=False)
	UserID = Column(String(250), nullable=False)

class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True)
	username = Column(String(50), nullable=False)
	email = Column(String(250), nullable=False)
	pw_hash = Column(String(250), nullable=False)

engine = create_engine('postgresql://iuser:user@db/libreria')
Base.metadata.create_all(engine)
