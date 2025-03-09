from flask import Flask, request, jsonify
import pandas as pd
import requests
import math
import pickle  # If you saved your trained model

app = Flask(__name__)

# Load trained model (Ensure you save your model as 'model.pkl')
with open("neuralcrave_model.pkl", "rb") as file:
    model = pickle.load(file)

# Nutritionix API credentials
API_ID = "16195d7f"
API_KEY = "ffb43ec448cb4ca9d05736726d48cb1c"
NUTRITIONIX_URL = "https://trackapi.nutritionix.com/v2/search/instant"

HEADERS = {
    "x-app-id": API_ID,
    "x-app-key": API_KEY
}

# Deficiency Mapping
deficiency_dict = {
    0: "Zinc Deficiency",
    1: "Magnesium Deficiency",
    2: "Iron Deficiency",
    3: "Hormonal Fluctuation",
    4: "Other",
    5: "Hormonal Changes",
    6: "Emotional/Stress Eating"
}

nutrient_map = {
    "Zinc Deficiency": "zinc",
    "Magnesium Deficiency": "magnesium",
    "Iron Deficiency": "iron",
    "Hormonal Fluctuation": "hormone-balancing foods",
    "Hormonal Changes": "hormone-balancing foods",
    "Emotional/Stress Eating": "stress-reducing foods"
}

# Prediction Interpretation
def interpret_prediction(pred_value):
    closest_int = round(pred_value)
    main_deficiency = deficiency_dict.get(closest_int, "Other")

    if math.isclose(pred_value, closest_int, abs_tol=0.3):
        related_deficiencies = {main_deficiency}
        if closest_int - 1 in deficiency_dict:
            related_deficiencies.add(deficiency_dict[closest_int - 1])
        if closest_int + 1 in deficiency_dict:
            related_deficiencies.add(deficiency_dict[closest_int + 1])
        return f"Maybe {main_deficiency}", list(related_deficiencies)
    
    return main_deficiency, [main_deficiency]

# Fetch Dietary Suggestions
def get_dietary_suggestions(deficiencies):
    suggestions = {}
    for deficiency in deficiencies:
        nutrient = nutrient_map.get(deficiency, "healthy foods")
        params = {"query": f"foods high in {nutrient}"}
        response = requests.get(NUTRITIONIX_URL, headers=HEADERS, params=params)

        if response.status_code == 200:
            data = response.json()
            food_items = [item["food_name"] for item in data.get("common", [])[:5]]
            suggestions[deficiency] = food_items if food_items else ["No food suggestions found."]
        else:
            suggestions[deficiency] = [f"API Error: {response.status_code}"]
    
    return suggestions

# API Route for Prediction
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        df_input = pd.DataFrame([data])
        
        # Make a prediction
        prediction = model.predict(df_input)[0]
        
        # Interpret the prediction
        main_deficiency, related_deficiencies = interpret_prediction(prediction)
        
        # Get dietary suggestions
        diet_suggestions = get_dietary_suggestions(related_deficiencies)

        response = {
            "prediction": main_deficiency,
            "related_deficiencies": related_deficiencies,
            "dietary_suggestions": diet_suggestions
        }

        return jsonify(response)
    
    except Exception as e:
        return jsonify({"error": str(e)})

# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
