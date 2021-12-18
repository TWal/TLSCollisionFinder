all: collision_finder

collision_finder: main.cpp
	g++ -std=c++20 -O3 main.cpp -o collision_finder
