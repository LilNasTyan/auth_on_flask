from flask import Blueprint, render_template, request, session, send_file, jsonify, redirect
import os
import tempfile
from datetime import datetime
from obfuscation import TextObfuscator
from utils import permission_required


obfuscation_bp = Blueprint("obfuscation", __name__, template_folder="../templates")


@obfuscation_bp.route("/obfuscate")
@permission_required('use_obfuscation')
def obfuscate_page():
    if "user_id" not in session:
        return redirect("/login")

    return render_template("obfuscation.html")


@obfuscation_bp.route("/api/obfuscate", methods=["POST"])
@permission_required('use_obfuscation')
def api_obfuscate():
    if "user_id" not in session:
        return jsonify({"error": "Ошибка авторизации"}), 401

    text = request.form.get("text", "")
    input_type = request.form.get("input_type", "text")
    output_type = request.form.get("output_type", "preview")

    # Загрузка из файла
    if input_type == "file" and 'file' in request.files:
        file = request.files['file']
        if file.filename:
            text = file.read().decode('utf-8')

    # Обфускация текста
    original_text = text
    obfuscated_text = TextObfuscator.obfuscate_text(text)

    # Обработка вывода
    if output_type == "file":
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(obfuscated_text)
            temp_path = temp_file.name

        return jsonify({
            "success": True,
            "download_url": f"/download/{os.path.basename(temp_path)}",
            "filename": f"obfuscated_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        })

    elif output_type == "console":
        # Вывод в консоль
        print("ОБФУСЦИРОВАННЫЙ ТЕКСТ:")
        print(obfuscated_text)

        return jsonify({
            "success": True,
            "message": "Текст выведен в консоль",
            "obfuscated_text": obfuscated_text
        })

    else:
        return jsonify({
            "success": True,
            "obfuscated_text": obfuscated_text,
            "stats": {
                "original_length": len(original_text),
                "obfuscated_length": len(obfuscated_text),
                "lines": obfuscated_text.count('\n') + 1
            }
        })


@obfuscation_bp.route("/api/obfuscate_cli", methods=["POST"])
@permission_required('use_obfuscation')
def api_obfuscate_cli():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Нет данных"}), 400

    text = data.get("text", "")
    source = data.get("source", "cli")
    filepath = data.get("filepath", "")

    if source == "file" and filepath:
        text = TextObfuscator.load_from_file(filepath)
        if text is None:
            return jsonify({"error": "Ошибка загрузки файла"}), 400

    # Обфускация
    obfuscated_text = TextObfuscator.obfuscate_text(text)

    output_type = data.get("output", "console")
    output_file = data.get("output_file", "")

    if output_type == "file" and output_file:
        success = TextObfuscator.save_to_file(output_file, obfuscated_text)
        if success:
            return jsonify({
                "success": True,
                "message": f"File saved to {output_file}",
                "file_size": len(obfuscated_text)
            })
        else:
            return jsonify({"error": "Ошибка сохранения файла"}), 500

    else:  # Вывод в консоль
        return obfuscated_text


@obfuscation_bp.route("/download/<filename>")
@permission_required('use_obfuscation')
def download_file(filename):
    # Скачивание файла
    if "user_id" not in session:
        return redirect("/login")

    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, filename)

    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=f"obfuscated_{filename}")

    return jsonify({"error": "Файл не найден"}), 404
