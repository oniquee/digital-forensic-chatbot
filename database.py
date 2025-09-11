from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

Base = declarative_base()

class Interaksi(Base):
    __tablename__ = 'interaksi'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(50))
    pesan = Column(Text)
    hasil_analisis = Column(Text)
    waktu = Column(DateTime, default=datetime.datetime.utcnow)

# Inisialisasi database SQLite
engine = create_engine('sqlite:///interaksi.db')
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)
