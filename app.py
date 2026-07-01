from flask import Flask, render_template, request, jsonify
from sqlalchemy import create_engine, inspect, text
import os

app = Flask(__name__)

# 1. Ana Sayfa Yönlendirmesi
@app.route('/')
def index():
    return render_template('index.html')

# 2. Veri Tabanı Bağlantı ve Bilgi Alma Yönlendirmesi
@app.route('/connect', methods=['POST'])
def connect_database():
    data = request.json
    db_type = data.get('db_type')
    host = data.get('host')
    port = data.get('port')
    user = data.get('user')
    password = data.get('password')
    database = data.get('database')
    
    try:
        # Veri tabanı türüne göre Connection String (URI) oluşturma
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'oracle':
            uri = f"oracle+oracledb://{user}:{password}@{host}:{port}/?service_name={database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'sqlite':
            uri = f"sqlite:///{database}"
        else:
            return jsonify({'success': False, 'message': 'Desteklenmeyen veri tabanı türü!'}), 400

        # Her veri tabanı sürücüsünün zaman aşımı (timeout) parametre adı farklıdır
        if db_type == 'postgresql':
            connect_args = {'connect_timeout': 5}
        elif db_type == 'mysql':
            connect_args = {'connect_timeout': 5}
        else:
            connect_args = {}

        # Motoru oluştur
        engine = create_engine(uri, connect_args=connect_args)
        
        # Bağlantıyı aç ve verileri çek
        with engine.connect() as connection:
            version_info = "Bilinmiyor"
            if db_type == 'postgresql':
                res = connection.execute(text("SELECT version();"))
                version_info = res.fetchone()[0]
            elif db_type == 'oracle':
                res = connection.execute(text("SELECT banner FROM v$version WHERE rownum = 1"))
                version_info = res.fetchone()[0]
            elif db_type == 'mysql':
                res = connection.execute(text("SELECT version();"))
                version_info = res.fetchone()[0]

            # Veri tabanındaki tabloları listele
            inspector = inspect(engine)
            tables = inspector.get_table_names()

        # Başarılı sonucu JSON olarak ön yüze (frontend) fırlat
        return jsonify({
            'success': True,
            'message': 'Bağlantı Başarılı!',
            'details': {
                'version': version_info,
                'tables': tables if tables else ["Hiç tablo bulunamadı veya erişim izni yok."]
            }
        })

    except Exception as e:
        # Bir hata oluşursa ön yüze hata mesajını gönder
        return jsonify({'success': False, 'message': f"Bağlantı Hatası: {str(e)}"}), 200
@app.route('/execute_sql', methods=['POST'])
def execute_sql():
    data = request.json
    db_type = data.get('db_type')
    host = data.get('host')
    port = data.get('port')
    user = data.get('user')
    password = data.get('password')
    database = data.get('database')
    sql_query = data.get('sql_query') # Arayüzden gelen SQL sorgusu
        
    if not sql_query:
        return jsonify({'success': False, 'message': 'Lütfen bir SQL sorgusu girin!'})

    # Veri tabanı bağlantı dizesini yeniden oluşturuyoruz
    try:
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'oracle':
            uri = f"oracle+oracledb://{user}:{password}@{host}:{port}/?service_name={database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'sqlite':
            uri = f"sqlite:///{database}"
        else:
            return jsonify({'success': False, 'message': 'Desteklenmeyen veri tabanı!'}), 400

        engine = create_engine(uri)
        
        with engine.connect() as connection:
            # SQL sorgusunu güvenli bir şekilde çalıştırılabilir formata çeviriyoruz
            result = connection.execute(text(sql_query))
            
            # Eğer sorgu bir SELECT sorgusuysa (veri döndürüyorsa)
            if result.returns_rows:
                columns = list(result.keys()) # Sütun isimleri (id, isim, bolum vb.)
                rows = [dict(row._mapping) for row in result.fetchall()] # Gelen satırlar
                
                # Tarih veya özel veri tipleri çıkarsa JSadscvdfvasdasasdasdasdsndjansjbhbjON hata vermesin diye string'e çeviriyoruz
                for row in rows:
                    for key, value in row.items():
                        if value is not None and not isinstance(value, (int, float, str, bool)):
                            row[key] = str(value)

                return jsonify({
                    'success': True,
                    'is_select': True,
                    'message': f"{len(rows)} satır getirildi.",
                    'columns': columns,
                    'rows': rows
                })
            else:
                # INSERT, UPDATE, DELETE veya CREATE sorguları için (satır döndürmeyenler)
                connection.commit() # Değişiklikleri veri tabanına kaydet
                return jsonify({
                    'success': True,
                    'is_select': False,
                    'message': f"Sorgu başarıyla çalıştırıldı. Etkilenen satır sayısı: {result.rowcount}"
                })

    except Exception as e:
        return jsonify({'success': False, 'message': f"SQL Hatası: {str(e)}"}), 200
        
# ====================================================================
# YENİ: ÖĞRENCİLERİ OTOMATİK LİSTELEME YÖNLENDİRMESİ (READ)
# ====================================================================
@app.route('/get_students', methods=['POST'])
def get_students():
    data = request.json
    db_type = data.get('db_type')
    host = data.get('host')
    port = data.get('port')
    user = data.get('user')
    password = data.get('password')
    database = data.get('database')

    try:
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        else:
            return jsonify({'success': False, 'message': 'Desteklenmeyen veri tabanı!'})

        engine = create_engine(uri)
        with engine.connect() as connection:
            # Tablo yoksa ortalama (GNO) sütunu dahil otomatik oluşturur
            if db_type == 'postgresql':
                connection.execute(text("""
                    CREATE TABLE IF NOT EXISTS ogrenciler (
                        id SERIAL PRIMARY KEY,
                        isim VARCHAR(100),
                        bolum VARCHAR(100),
                        ortalama NUMERIC(3,2) DEFAULT 0.00
                    );
                """))
                connection.commit()
                
                # Eğer tablo daha önceden oluştup içi boş kaldıysa ortalama sütununu zorla ekler
                try:
                    connection.execute(text("ALTER TABLE ogrenciler ADD COLUMN IF NOT EXISTS ortalama NUMERIC(3,2) DEFAULT 0.00;"))
                    connection.commit()
                except:
                    pass
            
            elif db_type == 'mysql':
                connection.execute(text("""
                    CREATE TABLE IF NOT EXISTS ogrenciler (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        isim VARCHAR(100),
                        bolum VARCHAR(100),
                        ortalama DECIMAL(3,2) DEFAULT 0.00
                    );
                """))
                connection.commit()

            # Öğrencileri ortalamalarıyla birlikte veri tabanından çeker
            res = connection.execute(text("SELECT id, isim, bolum, ortalama FROM ogrenciler ORDER BY id DESC;"))
            students = []
            for row in res.fetchall():
                mapping = dict(row._mapping)
                if mapping.get('ortalama') is not None:
                    mapping['ortalama'] = float(mapping['ortalama'])
                students.append(mapping)

        return jsonify({'success': True, 'students': students})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

    try:
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        else:
            return jsonify({'success': False, 'message': 'Bu özellik şu an PostgreSQL ve MySQL için aktiftir.'})

        engine = create_engine(uri)
        with engine.connect() as connection:
            # Önce eğer 'ogrenciler' tablosu yoksa otomatik oluştursun (Kullanıcıya kolaylık)
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS ogrenciler (
                    id SERIAL PRIMARY KEY,
                    isim VARCHAR(100),
                    bolum VARCHAR(100)
                );
            """))
            connection.commit()

            # Öğrencileri çek
            res = connection.execute(text("SELECT id, isim, bolum FROM ogrenciler ORDER BY id DESC;"))
            students = [dict(row._mapping) for row in res.fetchall()]

        return jsonify({'success': True, 'students': students})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# ====================================================================
# YENİ: ÖĞRENCİ EKLEME YÖNLENDİRMESİ (CREATE)
# ====================================================================
@app.route('/add_student', methods=['POST'])
def add_student():
    data = request.json
    db_type = data.get('db_type')
    host = data.get('host')
    port = data.get('port')
    user = data.get('user')
    password = data.get('password')
    database = data.get('database')
    
    student_name = data.get('student_name')
    student_dept = data.get('student_dept')
    student_avg = data.get('student_avg', 0.00) # Ön yüzden gelen ortalama (yoksa 0.00)

    if not student_name or not student_dept:
        return jsonify({'success': False, 'message': 'İsim ve Bölüm alanları boş bırakılamaz!'})

    try:
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        else:
            return jsonify({'success': False, 'message': 'Desteklenmeyen veri tabanı!'})

        engine = create_engine(uri)
        with engine.connect() as connection:
            # Sorguya 'ortalama' sütununu ve ':avg' parametresini ekledik
            connection.execute(
                text("INSERT INTO ogrenciler (isim, bolum, ortalama) VALUES (:name, :dept, :avg);"),
                {"name": student_name, "dept": student_dept, "avg": student_avg}
            )
            connection.commit()

        return jsonify({'success': True, 'message': 'Öğrenci başarıyla eklendi!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    
    # Eklenecek öğrenci bilgileri
        return jsonify({'success': True, 'message': 'Öğrenci başarıyla eklendi!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    # ====================================================================
# YENİ: ÖĞRENCİ SİLME YÖNLENDİRMESİ (DELETE)
# ====================================================================
@app.route('/delete_student', methods=['POST'])
def delete_student():
    data = request.json
    db_type = data.get('db_type')
    host = data.get('host')
    port = data.get('port')
    user = data.get('user')
    password = data.get('password')
    database = data.get('database')
    student_id = data.get('student_id') # Silinecek öğrencinin ID'si

    if not student_id:
        return jsonify({'success': False, 'message': 'Geçersiz Öğrenci ID!'})

    try:
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        else:
            return jsonify({'success': False, 'message': 'Desteklenmeyen veri tabanı!'})

        engine = create_engine(uri)
        with engine.connect() as connection:
            connection.execute(
                text("DELETE FROM ogrenciler WHERE id = :id;"),
                {"id": student_id}
            )
            connection.commit()

        return jsonify({'success': True, 'message': 'Öğrenci başarıyla silindi!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# ====================================================================
# YENİ: ÖĞRENCİ GÜNCELLEME YÖNLENDİRMESİ (UPDATE)
# ====================================================================
@app.route('/update_student', methods=['POST'])
def update_student():
    data = request.json
    db_type = data.get('db_type')
    host = data.get('host')
    port = data.get('port')
    user = data.get('user')
    password = data.get('password')
    database = data.get('database')
    
    student_id = data.get('student_id')
    student_name = data.get('student_name')
    student_dept = data.get('student_dept')
    student_avg = data.get('student_avg', 0.00) # Ön yüzden gelen güncel ortalama

    if not student_id or not student_name or not student_dept:
        return jsonify({'success': False, 'message': 'Tüm alanların doldurulması zorunludur!'})

    try:
        if db_type == 'postgresql':
            uri = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
        elif db_type == 'mysql':
            uri = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        else:
            return jsonify({'success': False, 'message': 'Desteklenmeyen veri tabanı!'})

        engine = create_engine(uri)
        with engine.connect() as connection:
            # UPDATE sorgusuna 'ortalama = :avg' parametresini iliştirdik
            connection.execute(
                text("UPDATE ogrenciler SET isim = :name, bolum = :dept, ortalama = :avg WHERE id = :id;"),
                {"name": student_name, "dept": student_dept, "avg": student_avg, "id": student_id}
            )
            connection.commit()

        return jsonify({'success': True, 'message': 'Öğrenci bilgileri güncellendi!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

    
# 3. Uygulamayı Başlatma Bloğu
if __name__ == '__main__':
    if not os.path.exists('templates'):
        os.makedirs('templates')
    app.run(debug=True, port=5000)
