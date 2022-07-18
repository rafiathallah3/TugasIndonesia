import requests, os
from bs4 import BeautifulSoup
from datetime import datetime
from flask import Flask, render_template, redirect, send_file, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt

"""
Masalah:
Kemungkinan database di heroku tereset, jadi diusahakan semua sudah lengkap 
"""

app = Flask(__name__)
app.secret_key = "Hayo loo kamu nonton..."

bcrypt = Bcrypt(app)

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Kau hancurkan aku dengan sikap mu'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), nullable=False, unique=True)
    name = db.Column(db.String(40))
    password = db.Column(db.String(80), nullable=False)

class NamaSiswa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(40), nullable=False, unique=True)

class Mingguan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tanggal = db.Column(db.String(21), nullable=False, unique=True)

class BayaranSiswa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_siswa = db.Column(db.Integer, nullable=False)
    id_tanggal = db.Column(db.Integer, nullable=False)
    bayaran = db.Column(db.Integer, nullable=False)

class Komentar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), nullable=False)
    waktu = db.Column(db.String(25), nullable=False)
    komentar = db.Column(db.String(100), nullable=False)

class BarangDiBeli(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(20), nullable=False)
    harga = db.Column(db.Integer, nullable=False)

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username", "class": "form-control"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Password", "class": "form-control"})

    submit = SubmitField("Masuk", render_kw={"class": "btn btn-primary float-right btn-block"})

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username", "class": "form-control"})
    name = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Nama", "class": "form-control"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Password", "class": "form-control"})

    submit = SubmitField("Buat akun", render_kw={"class": "btn btn-primary float-right btn-block"})

@login_manager.user_loader
def user_load(id):
    return User.query.get(id)

@app.route('/')
def utama():
    return render_template("utama.jinja")

@app.route('/bendahara')
@login_required
def bendahara():
    list_mingguan = Mingguan.query.all()
    list_barang = BarangDiBeli.query.all()
    list_bayaran = BayaranSiswa.query.all()
    
    dict_bayaran = {"mingguan": {x.id: 0 for x in list_mingguan}, "total": 0, "list_mingguan_enumerate": enumerate(list_mingguan), "list_barang_enumerate": enumerate(list_barang)}

    for i in list_bayaran:
        # if dict_bayaran["mingguan"].get(i.id_tanggal) is None:
        #     dict_bayaran["mingguan"].setdefault(i.id_tanggal, i.bayaran)
        #     continue
        dict_bayaran["mingguan"][i.id_tanggal] += i.bayaran
    dict_bayaran["total"] = sum(dict_bayaran["mingguan"].values())
    dict_bayaran["total"] -= sum(int(x.harga) for x in BarangDiBeli.query.all())

    return render_template("bendahara.jinja", user=current_user, list_user=NamaSiswa.query.all(), list_bayaran=list_bayaran, list_mingguan=list_mingguan, list_komentar=Komentar.query.all()[::-1], list_barang=list_barang, **dict_bayaran)

@app.route('/tambahinnama', methods=["POST"])
def tambahinnama():
    nama = NamaSiswa(nama=request.form['nama'])
    db.session.add(nama)
    db.session.commit()

    return redirect(url_for("bendahara"))

@app.route('/hapusinnama', methods=["POST"])
def hapusinnama():
    nama = NamaSiswa.query.filter_by(id=request.form['id_siswa'])
    if nama.first():
        BayaranSiswa.query.filter_by(id_siswa=nama.first().id).delete()
        nama.delete()
        db.session.commit()
    
    return redirect(url_for("bendahara"))

@app.route('/tambahinmingguan', methods=["POST"])
def tambahinmingguan():
    tahun, bulan, tanggal = request.form['tanggal'].split('-')
    nama = Mingguan(tanggal=f"{datetime.strptime(bulan, '%m').strftime('%b')} {tanggal}, {tahun}")
    db.session.add(nama)
    db.session.commit()

    return redirect(url_for("bendahara"))

@app.route('/hapusinmingguan', methods=["POST"])
def hapusinmingguan():
    if request.form.get("id_tanggal"):
        minggu = Mingguan.query.filter_by(id=request.form['id_tanggal'])
        if minggu.first():
            BayaranSiswa.query.filter_by(id_tanggal=minggu.first().id).delete()
            minggu.delete()
            db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/hapusinbarang", methods=["POST"])
def HapusinBarang():
    if request.form.get("id_barang"):
        barang = BarangDiBeli.query.filter_by(id=request.form['id_barang'])
        if barang.first():
            barang.delete()
            db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/bayarinsiswa", methods=["POST"])
def bayarinsiswa():
    if request.form.get("id_siswa") and request.form.get("id_tanggal") and request.form.get("bayaran"):
        if BayaranSiswa.query.filter_by(id_siswa=int(request.form['id_siswa']) ,id_tanggal=int(request.form['id_tanggal'])).count() < 1:
            bayaran = BayaranSiswa(id_siswa=int(request.form['id_siswa']), id_tanggal=int(request.form['id_tanggal']), bayaran=int(request.form["bayaran"]))
            db.session.add(bayaran)
            db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/ubahinbayaransiswa", methods=["POST"])
def ubahinbayaransiswa():
    if request.form.get("id_siswa") and request.form.get("id_tanggal") and request.form.get("bayaran"):
        bayaran = BayaranSiswa.query.filter_by(id_siswa=request.form['id_siswa'], id_tanggal=request.form['id_tanggal']).first()

        if bayaran:
            bayaran.bayaran = request.form['bayaran']
            db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/tambahinkomentar", methods=["POST"])
def TambahinKomentar():
    if request.form.get("komentar") and request.form.get('waktu'):
        d = datetime.strptime(" ".join(x for i, x in enumerate(request.form['waktu'].split(' ')) if i in range(1, 5)), "%b %d %Y %H:%M:%S")

        komentar = Komentar(username=current_user.name, komentar=request.form['komentar'], waktu=d.strftime("%d %B, %Y %H:%M"))
        db.session.add(komentar)
        db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/hapusinkomentar", methods=["POST"])
def HapusinKomentar():
    if request.form.get("id_komentar"):
        komentar = Komentar.query.filter_by(id=request.form['id_komentar'])
        komentar.delete()
        db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/dapatinbayaran")
@login_required
def DapatinBayaranDariMingguan():
    if request.args.get("id_tanggal") and request.args.get("id_siswa"):
        bayaran = BayaranSiswa.query.filter_by(id_siswa=request.args['id_siswa'], id_tanggal=request.args['id_tanggal']).first()
        print(request.args['id_siswa'], request.args['id_tanggal'])
        
        return {
            "bayaran": "0000" if bayaran is None else bayaran.bayaran
        }
    elif request.args.get("id_siswa"):
        bayaran = BayaranSiswa.query.filter_by(id_siswa=request.args['id_siswa']).all()

        return {
            "bayaran": {
                i.id_tanggal: Mingguan.query.filter_by(id=i.id_tanggal).first().tanggal
            } for i in bayaran
        }

    return redirect(url_for("bendahara"))

@app.route("/belibarang", methods=["POST"])
def belibarang():
    if request.form.get("nama") and request.form.get("harga"):
        barang = BarangDiBeli(nama=request.form['nama'], harga=request.form['harga'])
        db.session.add(barang)
        db.session.commit()

    return redirect(url_for("bendahara"))

@app.route("/dapatincetakan", methods=["GET"])
@login_required
def DapatinCetakan():
    if request.args.get("id_tanggal") and Mingguan.query.filter_by(id=request.args['id_tanggal']).first():
        semua_siswa = NamaSiswa.query.all()
        string_siswa = ""

        for i in semua_siswa:
            bayaran = BayaranSiswa.query.filter_by(id_siswa=i.id, id_tanggal=request.args['id_tanggal'])
            string_siswa += f"{i.id}. {i.nama}: {'0000' if not bayaran.first() else bayaran.first().bayaran} \n"

        return {
            "pesan": f"Minggu ke {request.args['id_tanggal']}\n{string_siswa}"
        }

    return {"pesan": "Tidak ada"}

@app.route('/download/database', methods=['GET'])
def download():
    p = "database.db"
    return send_file(p, as_attachment=True)

# @app.route("/ubahinhargakas", methods=["POST"])
# def ubahinhargakas():
#     if request.form.get("harga"):
#         session['hargakas'] = request.form['harga']

#     return redirect(url_for("bendahara"))

@app.route('/masuk', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("bendahara"))

    form = LoginForm()

    if form.validate_on_submit():
        akun = User.query.filter_by(username=form.username.data).first()
        if akun and bcrypt.check_password_hash(akun.password, form.password.data):
            login_user(akun)
            return redirect(url_for("bendahara"))

        # flash("Password salah! Mohon dicoba lagi")

        #Kemungkinan masuk dengan e-learning jadi kita buat akun baru
        with requests.session() as s:
            r = s.get("https://belajar.e-smanpul.com/siswa/login")
            soup = BeautifulSoup(r.content, 'lxml')
            r = s.post("https://belajar.e-smanpul.com/auth/proc/c2lzd2E=", {
                "_token": soup.select_one('[name="_token"]')['value'],
                "username": form.username.data,
                "password": form.password.data
            })
            soup = BeautifulSoup(r.content, 'lxml')
            nama = soup.select_one('[class*="profile-username"]')

            if nama:
                user = User(username=form.username.data, password=bcrypt.generate_password_hash(form.password.data), name=nama.text.strip())
                db.session.add(user)
                db.session.commit()

                login_user(user)
                return redirect(url_for("bendahara"))

    return render_template("login.jinja", form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("bendahara"))

    form = RegisterForm()

    if form.validate_on_submit():
        akun = User(username=form.username.data, password=bcrypt.generate_password_hash(form.username.data), name=form.name.data)
        db.session.add(akun)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.jinja", form=form)

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("utama"))

if __name__ == "__main__":
    app.run(port=4300, debug=True)