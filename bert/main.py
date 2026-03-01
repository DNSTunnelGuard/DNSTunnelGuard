

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/weight', methods=['GET'])
def get_weight_percentage():
    query = request.args.get('query', type=str)
    if not query:
        return jsonify({"error": "Missing or invalid 'query' parameter"}), 400

    dummy_weight_percentage = 0.42

    return jsonify({"weight_percentage": dummy_weight_percentage})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)