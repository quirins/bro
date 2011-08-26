// This file is automatically generated from dnp3.pac.

#ifndef dnp3_pac_h
#define dnp3_pac_h

#include <vector>

#include "binpac.h"


#include "binpac_bro.h"

namespace binpac {

namespace Dnp3 {
class ContextDnp3;
class Dnp3_PDU;
class Dnp3_Request;
class Dnp3_Response;
class Dnp3_Application_Request_Header;
class Dnp3_Application_Response_Header;
class Response_Internal_Indication;
class Request_Objects;
class Response_Objects;
class Object_Header;
class Range_Field_0;
class Range_Field_1;
class Range_Field_2;
class Range_Field_3;
class Range_Field_4;
class Range_Field_5;
class Object_With_Header;
class AnalogInput32woTime;
class AnalogInput16woTime;
class AnalogInput32wTime;
class AnalogInput16wTime;
class AnalogInputSPwoTime;
class AnalogInputDPwoTime;
class AnalogInputSPwTime;
class AnalogInputDPwTime;
enum function_codes_value {
	CONFIRM = 0,
	READ = 1,
	WRITE = 2,
	SELECT = 3,
	OPERATE = 4,
	DIRECT_OPERATE = 5,
	DIRECT_OPERATE_NR = 6,
	IMMED_FREEZE = 7,
	IMMED_FREEZE_NR = 8,
	FREEZE_CLEAR = 9,
	FREEZE_CLEAR_NR = 10,
	FREEZE_AT_TIME = 11,
	FREEZE_AT_TIME_NR = 12,
	COLD_RESTART = 13,
	WARM_RESTART = 14,
	INITIALIZE_DATA = 15,
	INITIALIZE_APPL = 16,
	START_APPL = 17,
	STOP_APPL = 18,
	SAVE_CONFIG = 19,
	ENABLE_UNSOLICITED = 20,
	DISABLE_UNSOLICITED = 21,
	ASSIGN_CLASS = 22,
	DELAY_MEASURE = 23,
	RECORD_CURRENT_TIME = 24,
	OPEN_FILE = 25,
	CLOSE_FILE = 26,
	DELETE_FILE = 27,
	GET_FILE_INFO = 28,
	AUTHENTICATE_FILE = 29,
	ABORT_FILE = 30,
	ACTIVATE_CONFIG = 31,
	AUTHENTICATE_REQ = 32,
	AUTHENTICATE_ERR = 33,
	RESPONSE = 129,
	UNSOLICITED_RESPONSE = 130,
	AUTHENTICATE_RESP = 131,
};
class Dnp3_Conn;
class Dnp3_Flow;
} // namespace Dnp3

int bytestring_to_int(const_bytestring const & s, int base);
double bytestring_to_double(const_bytestring const & s);
int bytestring_casecmp(const_bytestring const & s1, const_charptr const & s2);
bool bytestring_caseprefix(const_bytestring const & s1, const_charptr const & s2);
double network_time();
namespace Dnp3 {

class ContextDnp3
{
public:
	ContextDnp3(Dnp3_Conn * connection, Dnp3_Flow * flow);
	~ContextDnp3();
	
	// Member access functions
	Dnp3_Conn * connection() const { return connection_; }
	Dnp3_Flow * flow() const { return flow_; }
	
protected:
	Dnp3_Conn * connection_;
	Dnp3_Flow * flow_;
};


class Dnp3_PDU
{
public:
	Dnp3_PDU(bool is_orig);
	~Dnp3_PDU();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	int val_case_index() const	{ return val_case_index_; }
	Dnp3_Request * request() const
		{
		switch ( val_case_index() )
			{
			case 1:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:6:request", val_case_index(), "true");
				break;
			}
		return request_;
		}
	Dnp3_Response * response() const
		{
		switch ( val_case_index() )
			{
			case 0:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:7:response", val_case_index(), "false");
				break;
			}
		return response_;
		}
	bool is_orig() const { return is_orig_; }
	int byteorder() const { return byteorder_; }
	
protected:
	int val_case_index_;
	Dnp3_Request * request_;
	Dnp3_Response * response_;
	bool is_orig_;
	int byteorder_;
};


class Dnp3_Request
{
public:
	Dnp3_Request();
	~Dnp3_Request();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	Dnp3_Application_Request_Header * app_header() const { return app_header_; }
	int data_case_index() const	{ return data_case_index_; }
	vector<Request_Objects *> * objects() const
		{
		switch ( data_case_index() )
			{
			case 1:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:14:objects", data_case_index(), "READ");
				break;
			}
		return objects_;
		}
	bytestring const & unknown() const
		{
		return unknown_;
		}
	
protected:
	Dnp3_Application_Request_Header * app_header_;
	int data_case_index_;
	vector<Request_Objects *> * objects_;
	Request_Objects * objects__elem_;
	bytestring unknown_;
};


class Dnp3_Response
{
public:
	Dnp3_Response();
	~Dnp3_Response();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	Dnp3_Application_Response_Header * app_header() const { return app_header_; }
	int data_case_index() const	{ return data_case_index_; }
	bytestring const & unknown() const
		{
		return unknown_;
		}
	
protected:
	Dnp3_Application_Response_Header * app_header_;
	int data_case_index_;
	bytestring unknown_;
};


class Dnp3_Application_Request_Header
{
public:
	Dnp3_Application_Request_Header();
	~Dnp3_Application_Request_Header();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	uint8 application_control() const { return application_control_; }
	uint8 function_code() const { return function_code_; }
	
protected:
	uint8 application_control_;
	uint8 function_code_;
};


class Dnp3_Application_Response_Header
{
public:
	Dnp3_Application_Response_Header();
	~Dnp3_Application_Response_Header();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	uint8 application_control() const { return application_control_; }
	uint8 function_code() const { return function_code_; }
	Response_Internal_Indication * internal_indications() const { return internal_indications_; }
	
protected:
	uint8 application_control_;
	uint8 function_code_;
	Response_Internal_Indication * internal_indications_;
};


class Response_Internal_Indication
{
public:
	Response_Internal_Indication();
	~Response_Internal_Indication();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	uint8 first_octet() const { return first_octet_; }
	uint8 second_octet() const { return second_octet_; }
	
protected:
	uint8 first_octet_;
	uint8 second_octet_;
};


class Request_Objects
{
public:
	Request_Objects();
	~Request_Objects();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	Object_Header * object_header() const { return object_header_; }
	int data_case_index() const	{ return data_case_index_; }
	bytestring const & unknown() const
		{
		return unknown_;
		}
	
protected:
	Object_Header * object_header_;
	int data_case_index_;
	bytestring unknown_;
};


class Response_Objects
{
public:
	Response_Objects();
	~Response_Objects();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	Object_Header * object_header() const { return object_header_; }
	int data_case_index() const	{ return data_case_index_; }
	vector<AnalogInput32woTime *> * ai32wotime() const
		{
		switch ( data_case_index() )
			{
			case 8193:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:70:ai32wotime", data_case_index(), "((int) 0x2001)");
				break;
			}
		return ai32wotime_;
		}
	AnalogInput16woTime * ai16wotime() const
		{
		switch ( data_case_index() )
			{
			case 8194:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:71:ai16wotime", data_case_index(), "((int) 0x2002)");
				break;
			}
		return ai16wotime_;
		}
	AnalogInput32wTime * ai32wtime() const
		{
		switch ( data_case_index() )
			{
			case 8195:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:72:ai32wtime", data_case_index(), "((int) 0x2003)");
				break;
			}
		return ai32wtime_;
		}
	AnalogInput16wTime * ai16wtime() const
		{
		switch ( data_case_index() )
			{
			case 8196:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:73:ai16wtime", data_case_index(), "((int) 0x2004)");
				break;
			}
		return ai16wtime_;
		}
	AnalogInputSPwoTime * aispwotime() const
		{
		switch ( data_case_index() )
			{
			case 8197:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:74:aispwotime", data_case_index(), "((int) 0x2005)");
				break;
			}
		return aispwotime_;
		}
	AnalogInputDPwoTime * aidpwotime() const
		{
		switch ( data_case_index() )
			{
			case 8198:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:75:aidpwotime", data_case_index(), "((int) 0x2006)");
				break;
			}
		return aidpwotime_;
		}
	AnalogInputSPwTime * aispwtime() const
		{
		switch ( data_case_index() )
			{
			case 8199:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:76:aispwtime", data_case_index(), "((int) 0x2007)");
				break;
			}
		return aispwtime_;
		}
	AnalogInputDPwTime * aidpwtime() const
		{
		switch ( data_case_index() )
			{
			case 8200:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:77:aidpwtime", data_case_index(), "((int) 0x2008)");
				break;
			}
		return aidpwtime_;
		}
	
protected:
	Object_Header * object_header_;
	int data_case_index_;
	vector<AnalogInput32woTime *> * ai32wotime_;
	AnalogInput32woTime * ai32wotime__elem_;
	AnalogInput16woTime * ai16wotime_;
	AnalogInput32wTime * ai32wtime_;
	AnalogInput16wTime * ai16wtime_;
	AnalogInputSPwoTime * aispwotime_;
	AnalogInputDPwoTime * aidpwotime_;
	AnalogInputSPwTime * aispwtime_;
	AnalogInputDPwTime * aidpwtime_;
};


class Object_Header
{
public:
	Object_Header();
	~Object_Header();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint16 object_type_field() const { return object_type_field_; }
	uint8 qualifier_field() const { return qualifier_field_; }
	int range_field_case_index() const	{ return range_field_case_index_; }
	Range_Field_0 * range_field_0() const
		{
		switch ( range_field_case_index() )
			{
			case 0:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:86:range_field_0", range_field_case_index(), "((int) 0)");
				break;
			}
		return range_field_0_;
		}
	Range_Field_1 * range_field_1() const
		{
		switch ( range_field_case_index() )
			{
			case 1:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:87:range_field_1", range_field_case_index(), "((int) 1)");
				break;
			}
		return range_field_1_;
		}
	Range_Field_2 * range_field_2() const
		{
		switch ( range_field_case_index() )
			{
			case 2:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:88:range_field_2", range_field_case_index(), "((int) 2)");
				break;
			}
		return range_field_2_;
		}
	Range_Field_3 * range_field_3() const
		{
		switch ( range_field_case_index() )
			{
			case 3:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:89:range_field_3", range_field_case_index(), "((int) 3)");
				break;
			}
		return range_field_3_;
		}
	Range_Field_4 * range_field_4() const
		{
		switch ( range_field_case_index() )
			{
			case 4:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:90:range_field_4", range_field_case_index(), "((int) 4)");
				break;
			}
		return range_field_4_;
		}
	Range_Field_5 * range_field_5() const
		{
		switch ( range_field_case_index() )
			{
			case 5:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:91:range_field_5", range_field_case_index(), "((int) 5)");
				break;
			}
		return range_field_5_;
		}
	uint8 range_field_7() const
		{
		switch ( range_field_case_index() )
			{
			case 7:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:93:range_field_7", range_field_case_index(), "((int) 7)");
				break;
			}
		return range_field_7_;
		}
	uint16 range_field_8() const
		{
		switch ( range_field_case_index() )
			{
			case 8:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:94:range_field_8", range_field_case_index(), "((int) 8)");
				break;
			}
		return range_field_8_;
		}
	uint32 range_field_9() const
		{
		switch ( range_field_case_index() )
			{
			case 9:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:95:range_field_9", range_field_case_index(), "((int) 9)");
				break;
			}
		return range_field_9_;
		}
	uint8 range_field_b() const
		{
		switch ( range_field_case_index() )
			{
			case 11:
				break;  // OK
			default:
				throw ExceptionInvalidCase("./dnp3-protocol.pac:96:range_field_b", range_field_case_index(), "((int) 0xb)");
				break;
			}
		return range_field_b_;
		}
	bytestring const & unknown() const
		{
		return unknown_;
		}
	uint32 number_of_item() const { return number_of_item_; }
	
protected:
	uint16 object_type_field_;
	uint8 qualifier_field_;
	int range_field_case_index_;
	Range_Field_0 * range_field_0_;
	Range_Field_1 * range_field_1_;
	Range_Field_2 * range_field_2_;
	Range_Field_3 * range_field_3_;
	Range_Field_4 * range_field_4_;
	Range_Field_5 * range_field_5_;
	uint8 range_field_7_;
	uint16 range_field_8_;
	uint32 range_field_9_;
	uint8 range_field_b_;
	bytestring unknown_;
	uint32 number_of_item_;
};


class Range_Field_0
{
public:
	Range_Field_0();
	~Range_Field_0();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	uint8 start_index() const { return start_index_; }
	uint8 stop_index() const { return stop_index_; }
	
protected:
	uint8 start_index_;
	uint8 stop_index_;
};


class Range_Field_1
{
public:
	Range_Field_1();
	~Range_Field_1();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint16 start_index() const { return start_index_; }
	uint16 stop_index() const { return stop_index_; }
	
protected:
	uint16 start_index_;
	uint16 stop_index_;
};


class Range_Field_2
{
public:
	Range_Field_2();
	~Range_Field_2();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint32 start_index() const { return start_index_; }
	uint32 stop_index() const { return stop_index_; }
	
protected:
	uint32 start_index_;
	uint32 stop_index_;
};


class Range_Field_3
{
public:
	Range_Field_3();
	~Range_Field_3();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data);
	
	// Member access functions
	uint8 start_addr() const { return start_addr_; }
	uint8 stop_addr() const { return stop_addr_; }
	
protected:
	uint8 start_addr_;
	uint8 stop_addr_;
};


class Range_Field_4
{
public:
	Range_Field_4();
	~Range_Field_4();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint16 start_addr() const { return start_addr_; }
	uint16 stop_addr() const { return stop_addr_; }
	
protected:
	uint16 start_addr_;
	uint16 stop_addr_;
};


class Range_Field_5
{
public:
	Range_Field_5();
	~Range_Field_5();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint32 start_addr() const { return start_addr_; }
	uint32 stop_addr() const { return stop_addr_; }
	
protected:
	uint32 start_addr_;
	uint32 stop_addr_;
};


class Object_With_Header
{
public:
	Object_With_Header();
	~Object_With_Header();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	Object_Header * object_header() const { return object_header_; }
	
protected:
	Object_Header * object_header_;
};


class AnalogInput32woTime
{
public:
	AnalogInput32woTime();
	~AnalogInput32woTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	uint32 value() const { return value_; }
	
protected:
	uint8 flag_;
	uint32 value_;
};


class AnalogInput16woTime
{
public:
	AnalogInput16woTime();
	~AnalogInput16woTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	uint16 value() const { return value_; }
	
protected:
	uint8 flag_;
	uint16 value_;
};


class AnalogInput32wTime
{
public:
	AnalogInput32wTime();
	~AnalogInput32wTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	uint32 value() const { return value_; }
	vector<uint8> * time() const { return time_; }
	
protected:
	uint8 flag_;
	uint32 value_;
	vector<uint8> * time_;
	uint8 time__elem_;
};


class AnalogInput16wTime
{
public:
	AnalogInput16wTime();
	~AnalogInput16wTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	uint16 value() const { return value_; }
	vector<uint8> * time() const { return time_; }
	
protected:
	uint8 flag_;
	uint16 value_;
	vector<uint8> * time_;
	uint8 time__elem_;
};


class AnalogInputSPwoTime
{
public:
	AnalogInputSPwoTime();
	~AnalogInputSPwoTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	uint32 value() const { return value_; }
	
protected:
	uint8 flag_;
	uint32 value_;
};


class AnalogInputDPwoTime
{
public:
	AnalogInputDPwoTime();
	~AnalogInputDPwoTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	vector<uint32> * value() const { return value_; }
	
protected:
	uint8 flag_;
	vector<uint32> * value_;
	uint32 value__elem_;
};


class AnalogInputSPwTime
{
public:
	AnalogInputSPwTime();
	~AnalogInputSPwTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	uint32 value() const { return value_; }
	vector<uint8> * time() const { return time_; }
	
protected:
	uint8 flag_;
	uint32 value_;
	vector<uint8> * time_;
	uint8 time__elem_;
};


class AnalogInputDPwTime
{
public:
	AnalogInputDPwTime();
	~AnalogInputDPwTime();
	int Parse(const_byteptr const t_begin_of_data, const_byteptr const t_end_of_data, int t_byteorder);
	
	// Member access functions
	uint8 flag() const { return flag_; }
	vector<uint32> * value() const { return value_; }
	vector<uint8> * time() const { return time_; }
	
protected:
	uint8 flag_;
	vector<uint32> * value_;
	uint32 value__elem_;
	vector<uint8> * time_;
	uint8 time__elem_;
};


class Dnp3_Conn : public binpac::ConnectionAnalyzer
{
public:
	Dnp3_Conn(BroAnalyzer const & bro_analyzer);
	~Dnp3_Conn();
	
	// Member access functions
	Dnp3_Flow * upflow() const { return upflow_; }
	Dnp3_Flow * downflow() const { return downflow_; }
	BroAnalyzer const & bro_analyzer() const { return bro_analyzer_; }
	
	void NewData(bool is_orig, const_byteptr begin, const_byteptr end);
	void NewGap(bool is_orig, int gap_length);
	void FlowEOF(bool is_orig);
	
protected:
	Dnp3_Flow * upflow_;
	Dnp3_Flow * downflow_;
	BroAnalyzer bro_analyzer_;
};


class Dnp3_Flow : public binpac::FlowAnalyzer
{
public:
	Dnp3_Flow(Dnp3_Conn * connection, bool is_orig);
	~Dnp3_Flow();
	
	// Member access functions
	Dnp3_Conn * connection() const { return connection_; }
	bool is_orig() const { return is_orig_; }
	
	void NewData(const_byteptr t_begin_of_data, const_byteptr t_end_of_data);
	void NewGap(int gap_length);
	void FlowEOF();
	
	// Functions
	bool deliver_message(uint16 length);
	
protected:
	Dnp3_PDU * dataunit_;
	ContextDnp3 * context_;
	Dnp3_Conn * connection_;
	bool is_orig_;
};

} // namespace Dnp3
}  // namespace binpac
#endif /* dnp3_pac_h */