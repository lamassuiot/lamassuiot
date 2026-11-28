package migrations

func JSONSortKey() Migration {
	return Migration{Version: 8, Name: "large JSON sort keys", Statements: []string{
		`CREATE TYPE lamassu_json_sort_key AS OBJECT (
			sort_value CLOB,
			ORDER MEMBER FUNCTION compare_value(other lamassu_json_sort_key) RETURN NUMBER
		)`,
		`CREATE TYPE BODY lamassu_json_sort_key AS
			ORDER MEMBER FUNCTION compare_value(other lamassu_json_sort_key) RETURN NUMBER IS
				self_length NUMBER;
				other_length NUMBER;
				common_length NUMBER;
				position NUMBER := 1;
				chunk_chars PLS_INTEGER;
				self_text VARCHAR2(1000 CHAR);
				other_text VARCHAR2(1000 CHAR);
				self_raw RAW(4000);
				other_raw RAW(4000);
				difference NUMBER;
				self_byte NUMBER;
				other_byte NUMBER;
			BEGIN
				IF SELF.sort_value IS NULL THEN
					IF other.sort_value IS NULL THEN RETURN 0; ELSE RETURN -1; END IF;
				ELSIF other.sort_value IS NULL THEN
					RETURN 1;
				END IF;

				self_length := DBMS_LOB.GETLENGTH(SELF.sort_value);
				other_length := DBMS_LOB.GETLENGTH(other.sort_value);
				common_length := LEAST(self_length, other_length);
				WHILE position <= common_length LOOP
					chunk_chars := LEAST(1000, common_length - position + 1);
					self_text := DBMS_LOB.SUBSTR(SELF.sort_value, chunk_chars, position);
					other_text := DBMS_LOB.SUBSTR(other.sort_value, chunk_chars, position);
					self_raw := UTL_RAW.CAST_TO_RAW(self_text);
					other_raw := UTL_RAW.CAST_TO_RAW(other_text);
					difference := UTL_RAW.COMPARE(self_raw, other_raw);
					IF difference != 0 THEN
						IF difference > UTL_RAW.LENGTH(self_raw) THEN RETURN -1; END IF;
						IF difference > UTL_RAW.LENGTH(other_raw) THEN RETURN 1; END IF;
						self_byte := TO_NUMBER(RAWTOHEX(UTL_RAW.SUBSTR(self_raw, difference, 1)), 'XX');
						other_byte := TO_NUMBER(RAWTOHEX(UTL_RAW.SUBSTR(other_raw, difference, 1)), 'XX');
						IF self_byte < other_byte THEN RETURN -1; ELSE RETURN 1; END IF;
					END IF;
					position := position + chunk_chars;
				END LOOP;

				IF self_length < other_length THEN RETURN -1;
				ELSIF self_length > other_length THEN RETURN 1;
				END IF;
				RETURN 0;
			END compare_value;
		END;`,
	}}
}
