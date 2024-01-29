import random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import time

NUM_REPLICAS = 50
THRESHOLD = 10
SEED_SIZE = 50
VIEW_CHANGE_TIMEOUT = 2

keys = [RSA.generate(1024) for _ in range(NUM_REPLICAS)]
public_keys = [key.publickey() for key in keys]
private_keys = [key.exportKey() for key in keys]

class Value:
    def __init__(self, requests, signature):
        self.requests = requests
        self.signature = signature

    def get_requests(self):
        return self.requests

    def get_signature(self):
        return self.signature

class New_View:
    def __init__(self, state, signature, leader=0):
        self.state = state
        self.signature = signature
        self.leader = leader

    def get_state(self):
        return self.state

    def get_signature(self):
        return self.signature

    def get_leader(self):
        return self.leader

    def get_requests(self):
        return None

def weighted_choice(elements, weights, k):
    return random.choices(elements, weights=weights, k=k)

class Request:
    def __init__(self, client, operation, timestamp):
        self.client = client
        self.operation = operation
        self.timestamp = timestamp

    def get_client(self):
        return self.client

    def get_operation(self):
        return self.operation

    def get_timestamp(self):
        return self.timestamp

    def __str__(self):
        return f"Request(client={self.client}, operation={self.operation}, timestamp={self.timestamp})"


def collect_requests():
    operations = ['add', 'sub', 'mul', 'div', 'power']
    return [Request(f"client{i}", f"{op}({i}, {i+1})", 1612185600.0 + i) for i, op in enumerate(operations)]

def order_requests(requests):
    return sorted(requests, key=lambda r: r.get_client())

def is_leader(replica_id):
    return replica_id == 4  # 0-based index, so the 5th replica is index 4


import hashlib

def threshold_sign(requests):
    signers = random.sample(range(NUM_REPLICAS), THRESHOLD)
    signatures = []
    for i in signers:
        signer = PKCS1_v1_5.new(RSA.importKey(private_keys[i]))
        requests_str = str(requests)
        h = SHA256.new(str(requests).encode('utf-8'))
        signatures.append(signer.sign(h))
    return b''.join(signatures)

def broadcast(data):
    if isinstance(data, Value):
        requests = data.get_requests()
        if requests:
            formatted_requests = [(r.get_client(), r.get_operation(), r.get_timestamp()) for r in requests]
            print(f"Broadcasting value: {formatted_requests}")
        else:
            print("Broadcasting empty value")
    elif isinstance(data, New_View):
        print(f"Broadcasting new view: {data.get_state()}")

def receive_value():
    return Value(
        [
            Request("client1", "add(1, 2)", 1612185600.0),
            Request("client2", "sub(3, 4)", 1612185601.0),
            Request("client3", "mul(5, 6)", 1612185602.0),
            Request("client4", "div(7, 8)", 1612185603.0),
            Request("client5", "pow(9, 10)", 1612185604.0),
        ],
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'
    )

def threshold_verify(value):
    verifiers = random.sample(range(NUM_REPLICAS), THRESHOLD)
    signature = value.get_signature()
    requests = value.get_requests()
    signatures = [signature[i:i + 128] for i in range(0, len(signature), 128)]

    if len(signatures) < THRESHOLD:
        return False

    for i in verifiers:
        if i < len(signatures):
            verifier = PKCS1_v1_5.new(public_keys[i])
            h = SHA256.new(str(requests).encode('utf-8'))

            if not verifier.verify(h, signatures[i]):
                return False
        else:
            return False

    return True

def filter_requests(requests):
    byte_string = str(requests).encode()
    hex_string = SHA256.new(byte_string).hexdigest()
    integer = int(hex_string, 16)
    index = integer % len(requests)
    return requests[index]

def add(a, b):
    return a + b

def sub(a, b):
    return a - b

def mul(a, b):
    return a * b

def div(a, b):
    if b != 0:
        return a / b
    else:
        return "Division by zero error"

def power(a, b):
    return a ** b

operation_mapping = {
    'add': add,
    'sub': sub,
    'mul': mul,
    'div': div,
    'power': power,
}

def execute_request(request):
    operation = request.get_operation()

    if operation in operation_mapping:
        operands = [int(arg) for arg in operation.split('(')[1][:-1].split(',')]
        result = operation_mapping[operation](*operands)
        print(f"Executing request: {operation} => Result: {result}")
        return result
    else:
        print(f"Unsupported operation: {operation}")
        return None

def send_result(result, client):
    print(f"Sending result {result} to client {client}")

def report_faulty(leader):
    print(f"Reporting leader {leader} as faulty")

def modinv(a, m):
    # Dummy value for modular inverse
    return 1

def lagrange_interpolate(requests):
    # Generate a seed list with random values
    return [random.randint(1, 100) for _ in range(SEED_SIZE)]

def is_new_leader(algorithm, seed):
    if algorithm == "randomized":
        return random.choice([True, False])
    elif algorithm == "weighted":
        return random.choices([True, False], weights=[0.2, 0.8], k=1)[0]
    else:
        return False


def receive_new_view(new_view_message):
    received_signature = new_view_message.get_signature()

    if threshold_verify(new_view_message):
        update_state(new_view_message.get_state(), [])
        return True
    else:
        report_faulty(0)  # You can modify this to report the leader in a real scenario
        return False


def update_state(new_state, executed_requests):
    new_state.update(executed_requests)
    print(f"Updating state with new state: {new_state}")

def get_state():
    return {}

def execute_protocol(replica_id):
    print(f"Replica {replica_id} executing protocol")

    requests = collect_requests()
    ordered_requests = order_requests(requests)

    if is_leader(replica_id):
        value = Value(ordered_requests, threshold_sign(ordered_requests))
        broadcast(value)
        print(f"Leader {replica_id} broadcasting value: {value.get_requests()}")

    start_time = time.time()
    value = receive_value()
    if value is None:
        elapsed_time = time.time() - start_time
        print(f"Elapsed time: {elapsed_time}")
        if elapsed_time > VIEW_CHANGE_TIMEOUT:
            print("Waiting for more time...")
        else:
            print("Initiating view change...")
            report_faulty(replica_id)
            view_change(random.choice(["randomized", "weighted"]), replica_id)
        return

    # Process received value
    print(f"Replica {replica_id} received value: {value.get_requests()}")

    # Execute some requests (for demonstration purposes)
    for request in ordered_requests[:3]:
        result = execute_request(request)
        send_result(result, request.get_client())

    # Simulate a condition for initiating a view change
    if random.choice([True, False]):
        print(f"Simulating a condition for initiating view change...")
        report_faulty(replica_id)
        view_change(random.choice(["randomized", "weighted"]), replica_id)
        return

    # Continue with the protocol
    print(f"Replica {replica_id} continuing protocol execution...")
    # ...


def select_new_leader(seed, replica_id):
    # Convert the seed list into a hexadecimal string
    seed_str = str(seed)
    hex_str = hashlib.sha256(seed_str.encode()).hexdigest()

    # Convert the hexadecimal string into a list of integers
    int_list = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

    # Use the modulo operation to select the new leader from the list
    new_leader = replica_id
    while new_leader == replica_id:
        new_leader = int_list[0] % NUM_REPLICAS
        int_list = int_list[1:] # Remove the first element from the list

    return new_leader

def view_change(algorithm, replica_id):
    print(f"Replica {replica_id} initiating view change")
    seed = lagrange_interpolate(get_state())
    print(f"Seed before shuffle: {seed}")

    # Broadcast an empty value to initiate the view change
    empty_value = Value([], b'')
    broadcast(empty_value)

    # Receive the broadcasted value
    new_view_message = receive_new_view(empty_value)

    if new_view_message:
        random.shuffle(seed)
        print(f"Seed after shuffle: {seed}")

        # Use the select_new_leader function to choose the new leader
        new_leader = select_new_leader(seed, replica_id)
        new_view = New_View(get_state(), threshold_sign(get_state()), leader=new_leader)

        if receive_new_view(new_view):
            update_state(new_view.get_state(), [])
            execute_protocol(replica_id)
        else:
            report_faulty(new_view.get_leader())
            view_change(algorithm, replica_id)

# ...

for i in range(NUM_REPLICAS):
    execute_protocol(i)
