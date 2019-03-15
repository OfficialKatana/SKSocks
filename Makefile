SKSocks-Full : clipch.obj SKSocks.obj srvpch.obj SKSocks-server.obj
	g++ -o SKSocks-Cli.run -pthread -Ofast ./SKSocks/pch.obj ./SKSocks/SKSocks.obj
	g++ -o SKSocks-Server.run -pthread -Ofast ./SKSocks-server/pch.obj ./SKSocks-server/SKSocks-server.obj
clipch.obj : ./SKSocks/pch.cpp ./SKSocks/pch.h
	g++ -c ./SKSocks/pch.cpp -o ./SKSocks/pch.obj -Ofast
SKSocks.obj : ./SKSocks/SKSocks.cpp ./SKSocks/pch.h ./SKSocks/common.h
	g++ -c ./SKSocks/SKSocks.cpp -o ./SKSocks/SKSocks.obj -Ofast
srvpch.obj : ./SKSocks-server/pch.cpp ./SKSocks-server/pch.h
	g++ -c ./SKSocks-server/pch.cpp -o ./SKSocks-server/pch.obj -Ofast
SKSocks-server.obj : ./SKSocks-server/SKSocks-server.cpp ./SKSocks/common.h ./SKSocks-server/pch.h
	g++ -c ./SKSocks-server/SKSocks-server.cpp -Ofast -o ./SKSocks-server/SKSocks-server.obj

clean : 
	rm SKSocks-Cli.run ./SKSocks/SKSocks.obj ./SKSocks/pch.obj \
	SKSocks-Server.run ./SKSocks-server/SKSocks-server.obj ./SKSocks-server/pch.obj
