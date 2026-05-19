from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")

db = client["secureci"]

scan_collection = db["scan_history"]