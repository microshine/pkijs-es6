"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _Attribute = require("./Attribute");

var _Attribute2 = _interopRequireDefault(_Attribute);

var _ECPrivateKey = require("./ECPrivateKey");

var _ECPrivateKey2 = _interopRequireDefault(_ECPrivateKey);

var _RSAPrivateKey = require("./RSAPrivateKey");

var _RSAPrivateKey2 = _interopRequireDefault(_RSAPrivateKey);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var PrivateKeyInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for PrivateKeyInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PrivateKeyInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PrivateKeyInfo);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", PrivateKeyInfo.defaultValues("version"));
		/**
   * @type {AlgorithmIdentifier}
   * @description privateKeyAlgorithm
   */
		this.privateKeyAlgorithm = (0, _pvutils.getParametersValue)(parameters, "privateKeyAlgorithm", PrivateKeyInfo.defaultValues("privateKeyAlgorithm"));
		/**
   * @type {OctetString}
   * @description privateKey
   */
		this.privateKey = (0, _pvutils.getParametersValue)(parameters, "privateKey", PrivateKeyInfo.defaultValues("privateKey"));

		if ("attributes" in parameters)
			/**
    * @type {Array.<Attribute>}
    * @description attributes
    */
			this.attributes = (0, _pvutils.getParametersValue)(parameters, "attributes", PrivateKeyInfo.defaultValues("attributes"));

		if ("parsedKey" in parameters)
			/**
    * @type {ECPrivateKey|RSAPrivateKey}
    * @description Parsed public key value
    */
			this.parsedKey = (0, _pvutils.getParametersValue)(parameters, "parsedKey", PrivateKeyInfo.defaultValues("parsedKey"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if ("json" in parameters) this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(PrivateKeyInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PrivateKeyInfo.schema({
				names: {
					version: "version",
					privateKeyAlgorithm: {
						names: {
							blockName: "privateKeyAlgorithm"
						}
					},
					privateKey: "privateKey",
					attributes: "attributes"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PKCS8");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;
			this.privateKeyAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.privateKeyAlgorithm });
			this.privateKey = asn1.result.privateKey;

			if ("attributes" in asn1.result) this.attributes = Array.from(asn1.result.attributes, function (element) {
				return new _Attribute2.default({ schema: element });
			});

			switch (this.privateKeyAlgorithm.algorithmId) {
				case "1.2.840.113549.1.1.1":
					// RSA
					{
						var privateKeyASN1 = asn1js.fromBER(this.privateKey.valueBlock.valueHex);
						if (privateKeyASN1.offset !== -1) this.parsedKey = new _RSAPrivateKey2.default({ schema: privateKeyASN1.result });
					}
					break;
				case "1.2.840.10045.2.1":
					// ECDSA
					if ("algorithmParams" in this.privateKeyAlgorithm) {
						if (this.privateKeyAlgorithm.algorithmParams instanceof asn1js.ObjectIdentifier) {
							var _privateKeyASN = asn1js.fromBER(this.privateKey.valueBlock.valueHex);
							if (_privateKeyASN.offset !== -1) {
								this.parsedKey = new _ECPrivateKey2.default({
									namedCurve: this.privateKeyAlgorithm.algorithmParams.valueBlock.toString(),
									schema: _privateKeyASN.result
								});
							}
						}
					}
					break;
				default:
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output sequence
			var outputArray = [new asn1js.Integer({ value: this.version }), this.privateKeyAlgorithm.toSchema(), this.privateKey];

			if ("attributes" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: Array.from(this.attributes, function (element) {
						return element.toSchema();
					})
				}));
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			//region Return common value in case we do not have enough info fo making JWK
			if ("parsedKey" in this === false) {
				var object = {
					version: this.version,
					privateKeyAlgorithm: this.privateKeyAlgorithm.toJSON(),
					privateKey: this.privateKey.toJSON()
				};

				if ("attributes" in this) object.attributes = Array.from(this.attributes, function (element) {
					return element.toJSON();
				});

				return object;
			}
			//endregion

			//region Making JWK
			var jwk = {};

			switch (this.privateKeyAlgorithm.algorithmId) {
				case "1.2.840.10045.2.1":
					// ECDSA
					jwk.kty = "EC";
					break;
				case "1.2.840.113549.1.1.1":
					// RSA
					jwk.kty = "RSA";
					break;
				default:
			}

			var publicKeyJWK = this.parsedKey.toJSON();

			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = Object.keys(publicKeyJWK)[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var key = _step.value;

					jwk[key] = publicKeyJWK[key];
				}
			} catch (err) {
				_didIteratorError = true;
				_iteratorError = err;
			} finally {
				try {
					if (!_iteratorNormalCompletion && _iterator.return) {
						_iterator.return();
					}
				} finally {
					if (_didIteratorError) {
						throw _iteratorError;
					}
				}
			}

			return jwk;
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert JSON value into current object
   * @param {Object} json
   */

	}, {
		key: "fromJSON",
		value: function fromJSON(json) {
			if ("kty" in json) {
				switch (json.kty.toUpperCase()) {
					case "EC":
						this.parsedKey = new _ECPrivateKey2.default({ json: json });

						this.privateKeyAlgorithm = new _AlgorithmIdentifier2.default({
							algorithmId: "1.2.840.10045.2.1",
							algorithmParams: new asn1js.ObjectIdentifier({ value: this.parsedKey.namedCurve })
						});
						break;
					case "RSA":
						this.parsedKey = new _RSAPrivateKey2.default({ json: json });

						this.privateKeyAlgorithm = new _AlgorithmIdentifier2.default({
							algorithmId: "1.2.840.113549.1.1.1",
							algorithmParams: new asn1js.Null()
						});
						break;
					default:
						throw new Error("Invalid value for \"kty\" parameter: " + json.kty);
				}

				this.privateKey = new asn1js.OctetString({ valueHex: this.parsedKey.toSchema().toBER(false) });
			}
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return 0;
				case "privateKeyAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "privateKey":
					return new asn1js.OctetString();
				case "attributes":
					return [];
				default:
					throw new Error("Invalid member name for PrivateKeyInfo class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//PrivateKeyInfo ::= SEQUENCE {
			//    version Version,
			//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
			//    privateKey PrivateKey,
			//    attributes [0] Attributes OPTIONAL }
			//
			//Version ::= INTEGER {v1(0)} (v1,...)
			//
			//PrivateKey ::= OCTET STRING
			//
			//Attributes ::= SET OF Attribute

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [privateKeyAlgorithm]
    * @property {string} [privateKey]
    * @property {string} [attributes]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "" }), _AlgorithmIdentifier2.default.schema(names.privateKeyAlgorithm || {}), new asn1js.OctetString({ name: names.privateKey || "" }), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Repeated({
						name: names.attributes || "",
						value: _Attribute2.default.schema()
					})]
				})]
			});
		}
	}]);

	return PrivateKeyInfo;
}();
//**************************************************************************************


exports.default = PrivateKeyInfo;
//# sourceMappingURL=PrivateKeyInfo.js.map